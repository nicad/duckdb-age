# DuckDB Age Extension

A DuckDB extension that registers the 'age' secret type, enabling native secret management for [age encryption](https://github.com/FiloSottile/age) keys within DuckDB. This extension allows you to securely store and manage age encryption key pairs for use with other extensions like [file-tools](https://github.com/duckdb/file-tools-extension).

## Features

- **Native Secret Management**: Integrates with DuckDB's built-in secret management system
- **Age Key Validation**: Validates age public keys (`age1...`) and private keys (`AGE-SECRET-KEY-1...`)
- **File-based Keys**: Support for reading keys from external files (recommended for security)
- **Inline Keys**: Support for inline key specification
- **Key Redaction**: Private keys are automatically redacted in logs and error messages
- **Flexible Configuration**: Mix and match inline keys with file-based keys

## Installation

### Building from Source

1. Clone the repository with submodules:
```shell
git clone --recurse-submodules https://github.com/your-repo/duckdb-age.git
cd duckdb-age
```

2. Build the extension:
```shell
make
```

The build produces:
- `./build/release/duckdb` - DuckDB binary with age extension pre-loaded
- `./build/release/extension/age/age.duckdb_extension` - Loadable extension binary

## Usage

### Loading the Extension

```sql
LOAD 'age';
```

### Creating Age Secrets

#### Using Inline Keys
```sql
CREATE SECRET my_age_key (
    TYPE 'age',
    public_key 'age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p',
    private_key 'AGE-SECRET-KEY-1QTAYQ69LA4P3QQN0VQPSJMG2WHVSQPQ3SG2F55M0XWDE9VQN0SZQCGUGJ8',
    key_id 'personal_key'
);
```

#### Using File-based Keys (Recommended)
```sql
CREATE SECRET my_age_key (
    TYPE 'age',
    public_key_file '/path/to/public_key.txt',
    private_key_file '/path/to/private_key.txt',
    key_id 'file_key'
);
```

#### Mixed Approach
```sql
CREATE SECRET mixed_key (
    TYPE 'age',
    public_key 'age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p',
    private_key_file '/path/to/private_key.txt'
);
```

### Managing Secrets

#### List Age Secrets
```sql
SELECT name, type, provider FROM duckdb_secrets() WHERE type = 'age';
```

#### Drop Secrets
```sql
DROP SECRET my_age_key;
```

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `public_key` | VARCHAR | No* | Age public key (starts with `age1`) |
| `private_key` | VARCHAR | No* | Age private key (starts with `AGE-SECRET-KEY-1`) |
| `public_key_file` | VARCHAR | No* | Path to file containing public key |
| `private_key_file` | VARCHAR | No* | Path to file containing private key |
| `key_id` | VARCHAR | No | Optional identifier for the key pair |

*At least one key (public or private) must be specified. Cannot specify both inline and file versions of the same key type.

### Validation Rules

- Public keys must start with `age1`
- Private keys must start with `AGE-SECRET-KEY-1`
- Cannot specify both `public_key` and `public_key_file`
- Cannot specify both `private_key` and `private_key_file`
- Key files must exist and be readable
- Key files have a 1MB size limit
- Key files are automatically trimmed of whitespace

## Testing

### Running Tests

#### Quick Test Script
Run the comprehensive test script:
```shell
./test_extension.sh
```

#### Manual Testing via Make
Run the complete test suite:
```shell
make test
```

#### Individual Test Files
Run specific test files using the unittest runner:
```shell
# Note: .test files use DuckDB's test format and require the unittest runner
# Manual SQL testing is recommended for development
```

### Manual Testing

1. Start DuckDB with the extension:
```shell
./build/release/duckdb
```

2. Test basic functionality:
```sql
-- Load extension
LOAD 'age';

-- Verify extension loads
SELECT age_version();

-- Create test key files
.system echo 'age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p' > /tmp/test_pub.txt
.system echo 'AGE-SECRET-KEY-1QTAYQ69LA4P3QQN0VQPSJMG2WHVSQPQ3SG2F55M0XWDE9VQN0SZQCGUGJ8' > /tmp/test_priv.txt

-- Test file-based secret creation
CREATE SECRET test_key (
    TYPE 'age',
    public_key_file '/tmp/test_pub.txt',
    private_key_file '/tmp/test_priv.txt'
);

-- Verify secret creation
SELECT * FROM duckdb_secrets() WHERE type = 'age';

-- Clean up
DROP SECRET test_key;
```

### Test Coverage

The test suite covers:
- Basic secret creation with inline keys
- File-based key loading
- Validation of key formats
- Error handling for invalid keys
- Error handling for missing files
- Mutual exclusivity validation
- Secret listing and management

## Integration with Other Extensions

This extension is designed to work with other DuckDB extensions that support age encryption:

```sql
-- Example with file-tools extension (hypothetical)
LOAD 'age';
LOAD 'file_tools';

CREATE SECRET my_age_key (
    TYPE 'age',
    public_key_file '~/.age/key.pub',
    private_key_file '~/.age/key.priv'
);

-- Use the secret for encryption/decryption operations
-- SELECT age_encrypt_file('data.txt', 'encrypted.age', 'my_age_key');
```

## Security Considerations

- **File-based keys are recommended** over inline keys for production use
- Private keys are automatically marked for redaction in logs
- Use appropriate file permissions (e.g., `600`) on key files
- Store key files outside the database directory
- Consider using dedicated key management systems for production deployments

## Development

### Project Structure
```
duckdb-age/
├── src/
│   ├── age_extension.cpp     # Main extension implementation
│   └── include/
│       └── age_extension.hpp # Extension header
├── test/sql/
│   ├── age.test             # Basic extension tests
│   └── age_secret.test      # Secret functionality tests
├── extension_config.cmake   # Extension configuration
└── README.md               # This file
```

### Building for Development

1. Make changes to source files
2. Rebuild: `make`
3. Test: `make test`
4. Run specific tests: `./build/release/duckdb < test/sql/age_secret.test`

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Related Projects

- [age](https://github.com/FiloSottile/age) - Modern encryption tool
- [DuckDB](https://duckdb.org/) - In-process SQL OLAP database
- [DuckDB Extensions](https://duckdb.org/docs/extensions/overview) - DuckDB extension ecosystem