#define DUCKDB_EXTENSION_MAIN

#include "age_extension.hpp"
#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/extension_util.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/common/types/value.hpp"
#include <duckdb/parser/parsed_data/create_scalar_function_info.hpp>
#include <fstream>
#include <sstream>

// FFI declarations for Rust functions
extern "C" {
    struct CKeyPair {
        char* public_key;
        char* private_key;
    };
    
    struct CBytes {
        uint8_t* data;
        size_t len;
    };
    
    CKeyPair age_keygen_c();
    CBytes age_encrypt_c(const uint8_t* data, size_t data_len, const char* recipient);
    void free_c_string(char* s);
    void free_c_bytes(CBytes bytes);
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
        result->redact_keys.insert("private_key");  // Mark for redaction
    } else if (has_private_key_file) {
        auto file_path = named_params["private_key_file"].ToString();
        try {
            auto private_key = ReadKeyFromFile(file_path);
            if (!StringUtil::StartsWith(private_key, "AGE-SECRET-KEY-1")) {
                throw InvalidInputException("Age private key from file must start with 'AGE-SECRET-KEY-1'");
            }
            result->secret_map["private_key"] = private_key;
            result->redact_keys.insert("private_key");  // Mark for redaction
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
    
    *ConstantVector::GetData<string_t>(public_key_vector) = 
        StringVector::AddString(public_key_vector, keys.public_key);
    *ConstantVector::GetData<string_t>(private_key_vector) = 
        StringVector::AddString(private_key_vector, keys.private_key);
    
    // Free C strings
    free_c_string(keys.public_key);
    free_c_string(keys.private_key);
}

// Age encrypt function - encrypts data with a public key
static void AgeEncryptFunction(DataChunk &args, ExpressionState &state, Vector &result) {
    auto &data_vector = args.data[0];
    auto &recipient_vector = args.data[1];
    
    BinaryExecutor::Execute<string_t, string_t, string_t>(
        data_vector, recipient_vector, result, args.size(),
        [&](string_t data, string_t recipient) {
            // Call Rust FFI function
            CBytes encrypted = age_encrypt_c(
                reinterpret_cast<const uint8_t*>(data.GetData()),
                data.GetSize(),
                recipient.GetString().c_str()
            );
            
            if (encrypted.data == nullptr) {
                // Encryption failed - return NULL
                return string_t();
            }
            
            // Create DuckDB blob from encrypted data
            auto result_str = StringVector::AddString(result, 
                reinterpret_cast<const char*>(encrypted.data), encrypted.len);
            
            // Free the C bytes
            free_c_bytes(encrypted);
            
            return result_str;
        }
    );
}

// Dummy function to verify extension loads
static void AgeVersionFunction(DataChunk &args, ExpressionState &state, Vector &result) {
    auto &result_vector = result;
    result.SetVectorType(VectorType::CONSTANT_VECTOR);
    *ConstantVector::GetData<string_t>(result_vector) = StringVector::AddString(result_vector, DuckDB::LibraryVersion());
}

static void LoadInternal(DatabaseInstance &instance) {
    // Register the age secret type
    RegisterAgeSecretType(instance);
    
    // Register age_keygen function
    auto age_keygen_fun = ScalarFunction("age_keygen", {LogicalType::INTEGER}, 
        LogicalType::STRUCT({{"public_key", LogicalType::VARCHAR}, {"private_key", LogicalType::VARCHAR}}),
        AgeKeygenFunction);
    ExtensionUtil::RegisterFunction(instance, age_keygen_fun);
    
    // Register age_encrypt function
    auto age_encrypt_fun = ScalarFunction("age_encrypt", {LogicalType::BLOB, LogicalType::VARCHAR}, 
        LogicalType::BLOB, AgeEncryptFunction);
    ExtensionUtil::RegisterFunction(instance, age_encrypt_fun);
    
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