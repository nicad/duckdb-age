#define DUCKDB_EXTENSION_MAIN

#include "age_extension.hpp"
#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/extension_util.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/common/types/value.hpp"
#include "duckdb/catalog/catalog_transaction.hpp"
#include <duckdb/parser/parsed_data/create_scalar_function_info.hpp>
#include <fstream>
#include <sstream>

// FFI declarations for Rust functions
extern "C" {
struct CKeyPair {
	char *public_key;
	char *private_key;
};

struct CBytes {
	uint8_t *data;
	size_t len;
};

struct CResult {
	bool success;
	uint8_t *data;
	size_t len;
	char *error_message;
};

CKeyPair age_keygen_c();
CKeyPair age_keygen_from_seed_c(const uint8_t *seed, size_t seed_len);
CResult age_encrypt_c(const uint8_t *data, size_t data_len, const char *recipient);
CResult age_decrypt_c(const uint8_t *data, size_t data_len, const char *identity);
CResult age_encrypt_multi_c(const uint8_t *data, size_t data_len, const char *const *recipients, size_t recipients_len);
void free_c_string(char *s);
void free_c_bytes(CBytes bytes);
void free_c_result(CResult result);
}

namespace duckdb {

static string ReadKeyFromFile(const string &file_path) {
	std::ifstream file(file_path);
	if (!file.is_open()) {
		throw InvalidInputException("Key file does not exist or cannot be opened: " + file_path);
	}

	// Get file size
	file.seekg(0, std::ios::end);
	auto file_size = file.tellg();
	file.seekg(0, std::ios::beg);

	if (file_size > 1024 * 1024) { // 1MB limit
		throw InvalidInputException("Key file too large (max 1MB): " + file_path);
	}

	// Read content
	std::stringstream buffer;
	buffer << file.rdbuf();
	string content = buffer.str();

	// Trim whitespace
	StringUtil::Trim(content);

	return content;
}

static unique_ptr<BaseSecret> CreateAgeSecretFromConfig(ClientContext &context, CreateSecretInput &input) {
	auto scope = input.scope;
	auto result = make_uniq<KeyValueSecret>(scope, input.type, input.provider, input.name);

	// Get parameters
	auto &named_params = input.options;

	// Handle public key - either inline or from file
	bool has_public_key = named_params.find("public_key") != named_params.end();
	bool has_public_key_file = named_params.find("public_key_file") != named_params.end();

	if (has_public_key && has_public_key_file) {
		throw InvalidInputException("Cannot specify both 'public_key' and 'public_key_file'");
	}

	if (has_public_key) {
		auto public_key = named_params["public_key"].ToString();
		if (!StringUtil::StartsWith(public_key, "age1")) {
			throw InvalidInputException("Age public key must start with 'age1'");
		}
		result->secret_map["public_key"] = public_key;
	} else if (has_public_key_file) {
		auto file_path = named_params["public_key_file"].ToString();
		try {
			auto public_key = ReadKeyFromFile(file_path);
			if (!StringUtil::StartsWith(public_key, "age1")) {
				throw InvalidInputException("Age public key from file must start with 'age1'");
			}
			result->secret_map["public_key"] = public_key;
		} catch (const Exception &e) {
			throw InvalidInputException("Failed to read public key file: " + string(e.what()));
		}
	}

	// Handle private key - either inline or from file
	bool has_private_key = named_params.find("private_key") != named_params.end();
	bool has_private_key_file = named_params.find("private_key_file") != named_params.end();

	if (has_private_key && has_private_key_file) {
		throw InvalidInputException("Cannot specify both 'private_key' and 'private_key_file'");
	}

	if (has_private_key) {
		auto private_key = named_params["private_key"].ToString();
		if (!StringUtil::StartsWith(private_key, "AGE-SECRET-KEY-1")) {
			throw InvalidInputException("Age private key must start with 'AGE-SECRET-KEY-1'");
		}
		result->secret_map["private_key"] = private_key;
		result->redact_keys.insert("private_key"); // Mark for redaction
	} else if (has_private_key_file) {
		auto file_path = named_params["private_key_file"].ToString();
		try {
			auto private_key = ReadKeyFromFile(file_path);
			if (!StringUtil::StartsWith(private_key, "AGE-SECRET-KEY-1")) {
				throw InvalidInputException("Age private key from file must start with 'AGE-SECRET-KEY-1'");
			}
			result->secret_map["private_key"] = private_key;
			result->redact_keys.insert("private_key"); // Mark for redaction
		} catch (const Exception &e) {
			throw InvalidInputException("Failed to read private key file: " + string(e.what()));
		}
	}

	// Optional key_id
	if (named_params.find("key_id") != named_params.end()) {
		result->secret_map["key_id"] = named_params["key_id"].ToString();
	}

	return std::move(result);
}

static void RegisterAgeSecretType(DatabaseInstance &instance) {
	// Register the age secret type
	SecretType secret_type;
	secret_type.name = "age";
	secret_type.deserializer = KeyValueSecret::Deserialize<KeyValueSecret>;
	secret_type.default_provider = "config";

	ExtensionUtil::RegisterSecretType(instance, secret_type);

	// Register the config provider
	CreateSecretFunction config_fun = {"age", "config", CreateAgeSecretFromConfig};
	config_fun.named_parameters["public_key"] = LogicalType::VARCHAR;
	config_fun.named_parameters["private_key"] = LogicalType::VARCHAR;
	config_fun.named_parameters["public_key_file"] = LogicalType::VARCHAR;
	config_fun.named_parameters["private_key_file"] = LogicalType::VARCHAR;
	config_fun.named_parameters["key_id"] = LogicalType::VARCHAR;

	ExtensionUtil::RegisterFunction(instance, config_fun);
}

// Age keygen function - returns struct with public_key and private_key
static void AgeKeygenFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	// Call Rust FFI function
	CKeyPair keys = age_keygen_c();

	// Set result as constant vector since this function doesn't depend on input
	result.SetVectorType(VectorType::CONSTANT_VECTOR);

	// Get struct children vectors
	auto &struct_children = StructVector::GetEntries(result);
	auto &public_key_vector = *struct_children[0];
	auto &private_key_vector = *struct_children[1];

	// Set constant values
	public_key_vector.SetVectorType(VectorType::CONSTANT_VECTOR);
	private_key_vector.SetVectorType(VectorType::CONSTANT_VECTOR);

	*ConstantVector::GetData<string_t>(public_key_vector) = StringVector::AddString(public_key_vector, keys.public_key);
	*ConstantVector::GetData<string_t>(private_key_vector) =
	    StringVector::AddString(private_key_vector, keys.private_key);

	// Free C strings
	free_c_string(keys.public_key);
	free_c_string(keys.private_key);
}

// Age keygen_from_seed function - deterministic key generation from seed
static void AgeKeygenFromSeedFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &seed_vector = args.data[0];

	// Get struct children vectors
	auto &struct_children = StructVector::GetEntries(result);
	auto &public_key_vector = *struct_children[0];
	auto &private_key_vector = *struct_children[1];

	UnaryExecutor::ExecuteWithNulls<string_t, string_t>(
	    seed_vector, result, args.size(), [&](string_t seed, ValidityMask &mask, idx_t idx) {
		    // Call Rust FFI function
		    CKeyPair keys = age_keygen_from_seed_c(reinterpret_cast<const uint8_t *>(seed.GetData()), seed.GetSize());

		    // Set values in the struct vectors
		    auto public_key = StringVector::AddString(public_key_vector, keys.public_key);
		    auto private_key = StringVector::AddString(private_key_vector, keys.private_key);

		    FlatVector::GetData<string_t>(public_key_vector)[idx] = public_key;
		    FlatVector::GetData<string_t>(private_key_vector)[idx] = private_key;

		    // Free C strings
		    free_c_string(keys.public_key);
		    free_c_string(keys.private_key);

		    return string_t(); // Return dummy value, actual data is in child vectors
	    });
}

// Age encrypt function - encrypts data with a public key or secret name
static void AgeEncryptFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &data_vector = args.data[0];
	auto &recipient_vector = args.data[1];

	BinaryExecutor::Execute<string_t, string_t, string_t>(
	    data_vector, recipient_vector, result, args.size(), [&](string_t data, string_t recipient) {
		    string recipient_key = recipient.GetString();

		    // Check if this is a secret name (doesn't start with "age1")
		    if (!StringUtil::StartsWith(recipient_key, "age1")) {
			    // Try to resolve as secret name
			    auto &context = state.GetContext();
			    auto &secret_manager = SecretManager::Get(context);

			    try {
				    auto transaction = CatalogTransaction::GetSystemCatalogTransaction(context);
				    auto secret_entry = secret_manager.GetSecretByName(transaction, recipient_key);
				    if (secret_entry) {
					    // Cast to KeyValueSecret to access the secret values
					    const auto &kv_secret = dynamic_cast<const KeyValueSecret &>(*secret_entry->secret);
					    auto public_key_value = kv_secret.TryGetValue("public_key");
					    if (!public_key_value.IsNull()) {
						    recipient_key = public_key_value.ToString();
					    } else {
						    throw InvalidInputException("Secret '" + recipient_key + "' does not contain public_key");
					    }
				    } else {
					    throw InvalidInputException("Secret '" + recipient_key + "' not found");
				    }
			    } catch (const std::bad_cast &e) {
				    throw InvalidInputException("Secret '" + recipient_key + "' is not a KeyValueSecret");
			    } catch (const Exception &e) {
				    // If secret lookup fails, treat as invalid recipient key
				    throw InvalidInputException("Invalid age recipient key: " + recipient_key +
				                                " (not a valid age key or secret name)");
			    }
		    }

		    // Call Rust FFI function with resolved key
		    CResult encrypted =
		        age_encrypt_c(reinterpret_cast<const uint8_t *>(data.GetData()), data.GetSize(), recipient_key.c_str());

		    if (!encrypted.success) {
			    // Encryption failed - throw error with message from Rust
			    string error_msg = "Encryption failed";
			    if (encrypted.error_message != nullptr) {
				    error_msg = string(encrypted.error_message);
			    }
			    free_c_result(encrypted);
			    throw InvalidInputException(error_msg);
		    }

		    // Create DuckDB blob from encrypted data
		    auto result_str =
		        StringVector::AddString(result, reinterpret_cast<const char *>(encrypted.data), encrypted.len);

		    // Free the C result
		    free_c_result(encrypted);

		    return result_str;
	    });
}

// Age decrypt function - decrypts data with a private key or secret name
static void AgeDecryptFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &data_vector = args.data[0];
	auto &identity_vector = args.data[1];

	BinaryExecutor::Execute<string_t, string_t, string_t>(
	    data_vector, identity_vector, result, args.size(), [&](string_t data, string_t identity) {
		    string identity_key = identity.GetString();

		    // Check if this is a secret name (doesn't start with "AGE-SECRET-KEY-1")
		    if (!StringUtil::StartsWith(identity_key, "AGE-SECRET-KEY-1")) {
			    // Try to resolve as secret name
			    auto &context = state.GetContext();
			    auto &secret_manager = SecretManager::Get(context);

			    try {
				    auto transaction = CatalogTransaction::GetSystemCatalogTransaction(context);
				    auto secret_entry = secret_manager.GetSecretByName(transaction, identity_key);
				    if (secret_entry) {
					    // Cast to KeyValueSecret to access the secret values
					    const auto &kv_secret = dynamic_cast<const KeyValueSecret &>(*secret_entry->secret);
					    auto private_key_value = kv_secret.TryGetValue("private_key");
					    if (!private_key_value.IsNull()) {
						    identity_key = private_key_value.ToString();
					    } else {
						    throw InvalidInputException("Secret '" + identity_key + "' does not contain private_key");
					    }
				    } else {
					    throw InvalidInputException("Secret '" + identity_key + "' not found");
				    }
			    } catch (const std::bad_cast &e) {
				    throw InvalidInputException("Secret '" + identity_key + "' is not a KeyValueSecret");
			    } catch (const Exception &e) {
				    // If secret lookup fails, treat as invalid identity key
				    throw InvalidInputException("Invalid age identity key: " + identity_key +
				                                " (not a valid age key or secret name)");
			    }
		    }

		    // Call Rust FFI function with resolved key
		    CResult decrypted =
		        age_decrypt_c(reinterpret_cast<const uint8_t *>(data.GetData()), data.GetSize(), identity_key.c_str());

		    if (!decrypted.success) {
			    // Decryption failed - throw error with message from Rust
			    string error_msg = "Decryption failed";
			    if (decrypted.error_message != nullptr) {
				    error_msg = string(decrypted.error_message);
			    }
			    free_c_result(decrypted);
			    throw InvalidInputException(error_msg);
		    }

		    // Create DuckDB blob from decrypted data
		    auto result_str =
		        StringVector::AddString(result, reinterpret_cast<const char *>(decrypted.data), decrypted.len);

		    // Free the C result
		    free_c_result(decrypted);

		    return result_str;
	    });
}

// Age encrypt_multi function - encrypts data for multiple recipients
static void AgeEncryptMultiFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &data_vector = args.data[0];
	auto &recipients_vector = args.data[1];

	BinaryExecutor::Execute<string_t, list_entry_t, string_t>(
	    data_vector, recipients_vector, result, args.size(), [&](string_t data, list_entry_t recipients_list) {
		    // Get the list data
		    auto list_data = ListVector::GetData(recipients_vector);
		    auto list_size = recipients_list.length;
		    auto list_offset = recipients_list.offset;

		    if (list_size == 0) {
			    throw InvalidInputException("Recipients list cannot be empty");
		    }

		    // Resolve recipients to public keys
		    vector<string> resolved_recipients;
		    auto &context = state.GetContext();
		    auto &secret_manager = SecretManager::Get(context);

		    auto &list_child = ListVector::GetEntry(recipients_vector);
		    auto list_child_data = FlatVector::GetData<string_t>(list_child);

		    for (idx_t i = 0; i < list_size; i++) {
			    auto recipient = list_child_data[list_offset + i].GetString();

			    // Check if this is a secret name (doesn't start with "age1")
			    if (!StringUtil::StartsWith(recipient, "age1")) {
				    // Try to resolve as secret name
				    try {
					    auto transaction = CatalogTransaction::GetSystemCatalogTransaction(context);
					    auto secret_entry = secret_manager.GetSecretByName(transaction, recipient);
					    if (secret_entry) {
						    const auto &kv_secret = dynamic_cast<const KeyValueSecret &>(*secret_entry->secret);
						    auto public_key_value = kv_secret.TryGetValue("public_key");
						    if (!public_key_value.IsNull()) {
							    recipient = public_key_value.ToString();
						    } else {
							    throw InvalidInputException("Secret '" + recipient + "' does not contain public_key");
						    }
					    } else {
						    throw InvalidInputException("Secret '" + recipient + "' not found");
					    }
				    } catch (const std::bad_cast &e) {
					    throw InvalidInputException("Secret '" + recipient + "' is not a KeyValueSecret");
				    } catch (const Exception &e) {
					    throw InvalidInputException("Invalid recipient: " + recipient);
				    }
			    }

			    resolved_recipients.push_back(recipient);
		    }

		    // Convert to C-style array of strings
		    vector<const char *> recipient_ptrs;
		    for (const auto &r : resolved_recipients) {
			    recipient_ptrs.push_back(r.c_str());
		    }

		    // Call Rust FFI function
		    CResult encrypted = age_encrypt_multi_c(reinterpret_cast<const uint8_t *>(data.GetData()), data.GetSize(),
		                                            recipient_ptrs.data(), recipient_ptrs.size());

		    if (!encrypted.success) {
			    string error_msg = "Encryption failed";
			    if (encrypted.error_message != nullptr) {
				    error_msg = string(encrypted.error_message);
			    }
			    free_c_result(encrypted);
			    throw InvalidInputException(error_msg);
		    }

		    // Create DuckDB blob from encrypted data
		    auto result_str =
		        StringVector::AddString(result, reinterpret_cast<const char *>(encrypted.data), encrypted.len);

		    // Free the C result
		    free_c_result(encrypted);

		    return result_str;
	    });
}

// Dummy function to verify extension loads
static void AgeVersionFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &result_vector = result;
	result.SetVectorType(VectorType::CONSTANT_VECTOR);
	*ConstantVector::GetData<string_t>(result_vector) =
	    StringVector::AddString(result_vector, DuckDB::LibraryVersion());
}

static void LoadInternal(DatabaseInstance &instance) {
	// Register the age secret type
	RegisterAgeSecretType(instance);

	// Register age_keygen function
	auto age_keygen_fun = ScalarFunction(
	    "age_keygen", {},
	    LogicalType::STRUCT({{"public_key", LogicalType::VARCHAR}, {"private_key", LogicalType::VARCHAR}}),
	    AgeKeygenFunction);
	ExtensionUtil::RegisterFunction(instance, age_keygen_fun);

	// Register age_keygen_from_seed function
	auto age_keygen_from_seed_fun = ScalarFunction(
	    "age_keygen_from_seed", {LogicalType::BLOB},
	    LogicalType::STRUCT({{"public_key", LogicalType::VARCHAR}, {"private_key", LogicalType::VARCHAR}}),
	    AgeKeygenFromSeedFunction);
	ExtensionUtil::RegisterFunction(instance, age_keygen_from_seed_fun);

	// Register age_encrypt function
	auto age_encrypt_fun =
	    ScalarFunction("age_encrypt", {LogicalType::BLOB, LogicalType::VARCHAR}, LogicalType::BLOB, AgeEncryptFunction);
	ExtensionUtil::RegisterFunction(instance, age_encrypt_fun);

	// Register age_decrypt function
	auto age_decrypt_fun =
	    ScalarFunction("age_decrypt", {LogicalType::BLOB, LogicalType::VARCHAR}, LogicalType::BLOB, AgeDecryptFunction);
	ExtensionUtil::RegisterFunction(instance, age_decrypt_fun);

	// Register age_encrypt_multi function
	auto age_encrypt_multi_fun =
	    ScalarFunction("age_encrypt_multi", {LogicalType::BLOB, LogicalType::LIST(LogicalType::VARCHAR)},
	                   LogicalType::BLOB, AgeEncryptMultiFunction);
	ExtensionUtil::RegisterFunction(instance, age_encrypt_multi_fun);

	// Register a dummy function to verify extension loads
	auto age_version_fun = ScalarFunction("age_version", {}, LogicalType::VARCHAR, AgeVersionFunction);
	ExtensionUtil::RegisterFunction(instance, age_version_fun);
}

void AgeExtension::Load(DuckDB &db) {
	LoadInternal(*db.instance);
}

std::string AgeExtension::Name() {
	return "age";
}

std::string AgeExtension::Version() const {
#ifdef EXT_VERSION_AGE
	return EXT_VERSION_AGE;
#else
	return "";
#endif
}

} // namespace duckdb

extern "C" {

DUCKDB_EXTENSION_API void age_init(duckdb::DatabaseInstance &db) {
	duckdb::DuckDB db_wrapper(db);
	db_wrapper.LoadExtension<duckdb::AgeExtension>();
}

DUCKDB_EXTENSION_API const char *age_version() {
	return duckdb::DuckDB::LibraryVersion();
}
}

#ifndef DUCKDB_EXTENSION_MAIN
#error DUCKDB_EXTENSION_MAIN not defined
#endif
