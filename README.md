<!-- markdownlint-disable -->
<p align="center">
    <a href="https://github.com/GreyTeamToolbox/">
        <img src="https://cdn.wolfsoftware.com/assets/images/github/organisations/greyteamtoolbox/black-and-white-circle-256.png" alt="GreyTeamToolbox logo" />
    </a>
    <br />
    <a href="https://github.com/GreyTeamToolbox/hasher-package/actions/workflows/cicd.yml">
        <img src="https://img.shields.io/github/actions/workflow/status/GreyTeamToolbox/hasher-package/cicd.yml?branch=master&label=build%20status&style=for-the-badge" alt="Github Build Status" />
    </a>
    <a href="https://github.com/GreyTeamToolbox/hasher-package/blob/master/LICENSE.md">
        <img src="https://img.shields.io/github/license/GreyTeamToolbox/hasher-package?color=blue&label=License&style=for-the-badge" alt="License">
    </a>
    <a href="https://github.com/GreyTeamToolbox/hasher-package">
        <img src="https://img.shields.io/github/created-at/GreyTeamToolbox/hasher-package?color=blue&label=Created&style=for-the-badge" alt="Created">
    </a>
    <br />
    <a href="https://github.com/GreyTeamToolbox/hasher-package/releases/latest">
        <img src="https://img.shields.io/github/v/release/GreyTeamToolbox/hasher-package?color=blue&label=Latest%20Release&style=for-the-badge" alt="Release">
    </a>
    <a href="https://github.com/GreyTeamToolbox/hasher-package/releases/latest">
        <img src="https://img.shields.io/github/release-date/GreyTeamToolbox/hasher-package?color=blue&label=Released&style=for-the-badge" alt="Released">
    </a>
    <a href="https://github.com/GreyTeamToolbox/hasher-package/releases/latest">
        <img src="https://img.shields.io/github/commits-since/GreyTeamToolbox/hasher-package/latest.svg?color=blue&style=for-the-badge" alt="Commits since release">
    </a>
    <br />
    <a href="https://github.com/GreyTeamToolbox/hasher-package/blob/master/.github/CODE_OF_CONDUCT.md">
        <img src="https://img.shields.io/badge/Code%20of%20Conduct-blue?style=for-the-badge" />
    </a>
    <a href="https://github.com/GreyTeamToolbox/hasher-package/blob/master/.github/CONTRIBUTING.md">
        <img src="https://img.shields.io/badge/Contributing-blue?style=for-the-badge" />
    </a>
    <a href="https://github.com/GreyTeamToolbox/hasher-package/blob/master/.github/SECURITY.md">
        <img src="https://img.shields.io/badge/Report%20Security%20Concern-blue?style=for-the-badge" />
    </a>
    <a href="https://github.com/GreyTeamToolbox/hasher-package/issues">
        <img src="https://img.shields.io/badge/Get%20Support-blue?style=for-the-badge" />
    </a>
</p>

## Overview

**THIS IS WORK IN PROGRESS!!**

`Hasher` is a customizable hashing tool implemented in Python. It allows users to hash various data types such as strings, integers, floats, lists, dictionaries, bytes, and even files with a standalone, configurable hashing algorithm. It offers additional security features such as configurable rounds, block sizes, and hash lengths, as well as optional `salt` and `pepper` for each hash.

## Features
- Supports hashing of multiple data types: `str`, `int`, `float`, `list`, `dict`, `tuple`, `bytes`, and files.
- Customizable parameters:
  - `rounds`: Number of rounds for the hashing process.
  - `block_size`: Size of the data blocks used for hashing.
  - `hash_length`: Length of the final hash output.
  - `salt`: Optional salt to add randomness to the hash.
  - `pepper`: An additional user-defined key that acts as a second salt.
- Provides both `base64` and `hex` output formats.
- Standalone script that does not depend on external libraries like `hashlib` or `hmac`.

## Installation
Simply download or clone this repository. No additional libraries are required.

## Usage

### Import and Initialize
```python
from configurable_hasher import ConfigurableHasher

# Initialize the hasher with custom parameters
hasher = ConfigurableHasher(
    rounds=100,
    block_size=512,
    hash_length=256,
    salt="custom_salt",
    pepper="extra_secret_pepper",
    output_format="base64"
)
```

### Hashing Data
```python
# Hash a string
data = "hello world"
hash_value = hasher.hash(data)
print(f"Hash of '{data}': {hash_value}")

# Hash an integer
integer_data = 12345
integer_hash = hasher.hash(integer_data)
print(f"Hash of {integer_data}: {integer_hash}")

# Hash a file
file_path = "example.txt"
file_hash = hasher.hash_file(file_path)
print(f"Hash of file '{file_path}': {file_hash}")
```

### Validating Hashes
To ensure the integrity of a hashed item, use the `validate` or `validate_file` method to compare the computed hash with an existing hash.

```python
# Validate a string hash
is_valid = hasher.validate(data, hash_value)
print(f"Is the hash valid? {is_valid}")

# Validate a file hash
is_file_valid = hasher.validate_file(file_path, file_hash)
print(f"Is the file hash valid? {is_file_valid}")
```

### Example Use Cases
- **Data Integrity Verification**: Use this tool to verify if data has been altered by comparing the hash before and after.
- **Password Storage**: Store passwords as salted and hashed strings for enhanced security.
- **File Change Detection**: Monitor changes in files by hashing their content and comparing it with stored hash values.

## Parameters
The following parameters can be configured in the `ConfigurableHasher` class:

- `rounds` (int): Number of rounds to use in the hashing algorithm. Minimum is `64`.
- `block_size` (int): Size of the data blocks for hashing in bits, must be between `128` and `2048`. Adjusted to be a multiple of `64`.
- `hash_length` (int): Length of the final hash output in bits, up to `512`.
- `salt` (Any): Optional salt for the hash. Accepts `str`, `int`, `float`, `list`, `dict`, `tuple`, and `bytes`. It is converted to bytes and truncated/padded to `16` bytes.
- `pepper` (Any): Optional pepper for the hash. Accepts the same types as `salt`, converted to bytes and truncated/padded to `16` bytes.
- `output_format` (str): Output format of the hash, either `'hex'` or `'base64'`.

## Supported Data Types
The `hash` method accepts a variety of data types:
- `str`: String data.
- `int`: Integer data (signed and unsigned).
- `float`: Floating-point numbers.
- `list`: Lists containing any of the supported data types.
- `dict`: Dictionaries with string keys and supported data types as values.
- `tuple`: Tuples containing any of the supported data types.
- `bytes`: Raw byte data.

## Limitations
- **Integer Size**: Integers are constrained by the `block_size` to prevent overflow errors. The maximum size is capped based on the block size in bits.
- **File Size**: The maximum file size is limited by the available memory, as the file is processed in blocks equal to `block_size // 8`.
  
## Security Considerations
The `ConfigurableHasher` offers a flexible and customizable hashing approach, but it's important to understand the security limitations:
- This hashing implementation is not cryptographically secure compared to standard algorithms like `SHA-256` or `bcrypt`.
- Suitable for data integrity checks or non-critical hashing needs, but not recommended for highly sensitive information such as password hashing in a production environment.
- **Salting**: The script allows for a fixed `salt` and `pepper`, making it easier to validate hashes but less secure than dynamic salting for each hash. Always use unique salts when possible for added security.


<br />
<p align="right"><a href="https://wolfsoftware.com/"><img src="https://img.shields.io/badge/Created%20by%20Wolf%20on%20behalf%20of%20Wolf%20Software-blue?style=for-the-badge" /></a></p>
