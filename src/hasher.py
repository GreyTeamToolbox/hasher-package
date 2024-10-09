"""
Hasher: A customizable hashing algorithm.

This script provides a hashing utility that can hash various data types (str, int, float, list, dict, bytes)
as well as files. It offers configurable rounds, block size, hash length, and optional salt and pepper.
It does not rely on external libraries like hashlib, making it fully standalone. It includes methods for
hashing data, hashing files, and validating hashes.

Usage:
    hasher = Hasher()
    hash_value = hasher.hash("sample data")
    is_valid = hasher.validate("sample data", hash_value)
    file_hash = hasher.hash_file("path/to/file.txt")
    is_file_valid = hasher.validate_file("path/to/file.txt", file_hash)
"""

import os
import struct
import json
import base64
from typing import Any, Generator, Optional


class HashingError(Exception):
    """Custom exception class for hashing errors."""
    pass


class Hasher:
    """
    Hasher: A standalone, customizable hashing class.

    This class provides configurable hashing for various data types and files, with customizable parameters
    such as the number of rounds, block size, hash length, and optional salt and pepper for additional security.
    The hashing implementation is standalone and does not rely on external libraries like hashlib.

    Attributes:
        rounds (int): Number of rounds of hashing.
        block_size (int): Size of each data block in bits.
        hash_length (int): Desired length of the final hash in bits.
        salt (bytes, optional): Optional salt for hashing, converted to bytes if provided.
        output_format (str): Format of the output hash, either 'hex' or 'base64'.
        pepper (bytes, optional): Optional pepper for hashing, converted to bytes if provided.
    """

    def __init__(self, rounds: int = 64, block_size: int = 512, hash_length: int = 256,
                 salt: Optional[Any] = None, output_format: str = 'hex', pepper: Optional[Any] = 'default_pepper') -> None:
        """
        Initializes the Hasher with customizable parameters.

        Args:
            rounds (int): Number of rounds of hashing, minimum of 64.
            block_size (int): Size of each data block in bits, between 128 and 2048.
            hash_length (int): Desired length of the final hash in bits, up to 512.
            salt (Any, optional): Optional salt for hashing, will be converted to bytes.
            output_format (str): Format of the output hash, either 'hex' or 'base64'.
            pepper (Any, optional): Optional pepper for hashing, will be converted to bytes.
        """
        self.block_size = self._validate_block_size(block_size)
        self.rounds = self._validate_rounds(rounds)
        self.hash_length = self._validate_hash_length(hash_length)
        self.salt = self._validate_salt(salt) if salt is not None else None
        self.output_format = output_format
        self.pepper = self._validate_pepper(pepper)

    def _validate_rounds(self, rounds: int) -> int:
        """
        Validates and ensures that the number of rounds is at least 64.

        Args:
            rounds (int): The desired number of hashing rounds.

        Returns:
            int: The validated number of rounds.
        """
        if rounds < 64:
            print("Warning: Rounds must be at least 64. Setting to 64.")
            rounds = 64
        return rounds

    def _validate_block_size(self, block_size: int) -> int:
        """
        Validates and adjusts the block size within acceptable bounds.

        Args:
            block_size (int): Desired block size in bits.

        Returns:
            int: The validated and adjusted block size.
        """
        if block_size < 128:
            raise ValueError("Block size too small. Minimum is 128 bits.")
        if block_size > 2048:
            print("Warning: Block size is very large. Capping to 2048 bits.")
            return 2048
        if block_size % 64 != 0:
            adjusted_block_size = (block_size // 64 + 1) * 64
            print(f"Warning: Block size should be a multiple of 64. Adjusting to {adjusted_block_size}.")
            return adjusted_block_size
        return block_size

    def _validate_hash_length(self, hash_length: int) -> int:
        """
        Validates and adjusts the hash length within acceptable bounds.

        Args:
            hash_length (int): Desired hash length in bits.

        Returns:
            int: The validated and adjusted hash length.
        """
        if hash_length > 512:
            print("Warning: Hash length is very large. Capping to 512 bits.")
            return 512
        if hash_length > self.block_size:
            print(f"Warning: Hash length cannot exceed block size. Adjusting to {self.block_size}.")
            return self.block_size
        if hash_length % 8 != 0:
            adjusted_hash_length = (hash_length // 8) * 8
            print(f"Warning: Hash length should be a multiple of 8. Adjusting to {adjusted_hash_length}.")
            return adjusted_hash_length
        return hash_length

    def _validate_salt(self, salt: Any) -> bytes:
        """
        Validates the salt and adjusts its length to 16 bytes if needed.

        Args:
            salt (Any): The salt value, which can be any type supported by _convert_data_to_bytes.

        Returns:
            bytes: A 16-byte salt, padded or truncated as necessary.
        """
        salt = self._convert_data_to_bytes(salt)
        if len(salt) < 16:
            salt = salt + b'\0' * (16 - len(salt))
            print("Warning: Salt is less than 16 bytes. Padding to 16 bytes.")
        elif len(salt) > 16:
            salt = salt[:16]
            print("Warning: Salt is more than 16 bytes. Truncating to 16 bytes.")
        return salt

    def _validate_pepper(self, pepper: Any) -> bytes:
        """
        Validates the pepper and adjusts its length to 16 bytes if needed.

        Args:
            pepper (Any): The pepper value, which can be any type supported by _convert_data_to_bytes.

        Returns:
            bytes: A 16-byte pepper, padded or truncated as necessary.
        """
        pepper = self._convert_data_to_bytes(pepper)
        if len(pepper) < 16:
            pepper = pepper + b'\0' * (16 - len(pepper))
            print("Warning: Pepper is less than 16 bytes. Padding to 16 bytes.")
        elif len(pepper) > 16:
            pepper = pepper[:16]
            print("Warning: Pepper is more than 16 bytes. Truncating to 16 bytes.")
        return pepper

    def _convert_data_to_bytes(self, data: Any) -> bytes:
        """
        Converts various data types to bytes for hashing.

        Args:
            data (Any): The data to be converted. Supported types include str, int, float, bytes, list, dict, and tuple.

        Returns:
            bytes: The byte representation of the data.
        """
        if isinstance(data, str):
            return data.encode('utf-8')
        if isinstance(data, int):
            data = abs(data) % (1 << self.block_size)  # Constrain integer size
            byte_length = (self.block_size + 7) // 8
            return data.to_bytes(byte_length, byteorder='big', signed=False)
        if isinstance(data, float):
            return struct.pack('>d', data)
        if isinstance(data, (list, dict, tuple)):
            return json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')
        if isinstance(data, bytes):
            return data
        raise TypeError("Unsupported data type. Supported types: str, int, float, bytes, list, dict, tuple.")

    def _initialize_vector(self, data: bytes) -> bytes:
        """
        Initializes the hashing vector using the data and salt.

        Args:
            data (bytes): The data to be hashed.

        Returns:
            bytes: The initialization vector for hashing, based on data and salt.
        """
        data_hash = int.from_bytes(self._convert_data_to_bytes(abs(hash(data)) % (1 << self.block_size)), 'big')
        base_iv = int.from_bytes(self.salt or os.urandom(16), 'big')
        iv = (base_iv ^ data_hash) % (1 << self.block_size)
        return iv.to_bytes(self.block_size // 8, 'big')[:self.hash_length // 8]

    def _mix(self, block: bytes, hash_value: bytes, salt_value: bytes) -> bytes:
        """
        Mixes the hash_value with the block and salt_value for each round.

        Args:
            block (bytes): The current data block being hashed.
            hash_value (bytes): The current hash value.
            salt_value (bytes): Salt value to add randomness to the mixing process.

        Returns:
            bytes: The mixed hash value after processing.
        """
        block_hash = abs(hash(block)) % (1 << self.block_size)
        block_hash = int.from_bytes(self._convert_data_to_bytes(block_hash), 'big')
        mixed = int.from_bytes(hash_value, 'big') ^ block_hash ^ int.from_bytes(salt_value, 'big')
        for _ in range(self.rounds):
            mixed = (mixed * 0x5bd1e995 + 0x1b873593) % (1 << self.block_size)
            mixed = ((mixed << 13) | (mixed >> (self.block_size - 13))) & ((1 << self.block_size) - 1)
            mixed ^= mixed >> 7
        return mixed.to_bytes(self.block_size // 8, 'big')

    def hash(self, data: Any, temp_salt: Optional[bytes] = None) -> str:
        """
        Hashes any data type into a string representation.

        Args:
            data (Any): The data to be hashed.
            temp_salt (bytes, optional): A temporary salt for hashing.

        Returns:
            str: The resulting hash in the specified output format.
        """
        salt_used = temp_salt or self.salt or os.urandom(16)
        peppered_salt = bytes(a ^ b for a, b in zip(salt_used, self.pepper))
        data = self._convert_data_to_bytes(data)
        hash_value = self._initialize_vector(data)
        mask = (1 << 128) - 1

        for i, block in enumerate(self._split_into_blocks(data)):
            block_dynamic_salt = ((int.from_bytes(peppered_salt, 'big') ^ int.from_bytes(hash_value, 'big') ^ int.from_bytes(block, 'big') ^ i) & mask).to_bytes(16, 'big')  # noqa
            hash_value = self._mix(block, hash_value, block_dynamic_salt)

        final_hash = hash_value[:self.hash_length // 8]
        combined_output = salt_used + final_hash
        return base64.urlsafe_b64encode(combined_output).decode('utf-8')

    def hash_file(self, file_path: str, temp_salt: Optional[bytes] = None) -> str:
        """
        Hashes a file's contents.

        Args:
            file_path (str): Path to the file.
            temp_salt (bytes, optional): A temporary salt for hashing.

        Returns:
            str: The resulting file hash in the specified output format.
        """
        salt_used = temp_salt or self.salt or os.urandom(16)
        peppered_salt = bytes(a ^ b for a, b in zip(salt_used, self.pepper))
        hash_value = self._initialize_vector(peppered_salt)
        mask = (1 << 128) - 1

        try:
            with open(file_path, 'rb') as f:
                for i in range(self.rounds):
                    block = f.read(self.block_size // 8)
                    if not block:
                        break
                    block_dynamic_salt = ((int.from_bytes(peppered_salt, 'big') ^ int.from_bytes(hash_value, 'big') ^ int.from_bytes(block, 'big') ^ i) & mask).to_bytes(16, 'big')  # noqa
                    hash_value = self._mix(block, hash_value, block_dynamic_salt)
        except OSError as e:
            raise HashingError(f"Error reading file '{file_path}'") from e

        final_hash = hash_value[:self.hash_length // 8]
        combined_output = salt_used + final_hash
        return base64.urlsafe_b64encode(combined_output).decode('utf-8')

    def validate(self, data: Any, given_hash: str) -> bool:
        """
        Validates a hash by comparing it with a computed hash of the data.

        Args:
            data (Any): The data to be validated.
            given_hash (str): The hash to compare against.

        Returns:
            bool: True if the hashes match, False otherwise.
        """
        decoded = base64.urlsafe_b64decode(given_hash)
        salt_len = 16
        salt = decoded[:salt_len]
        computed_hash = self.hash(data, temp_salt=salt)
        return computed_hash == given_hash

    def validate_file(self, file_path: str, given_hash: str) -> bool:
        """
        Validates a file's hash by comparing it with a computed hash.

        Args:
            file_path (str): Path to the file.
            given_hash (str): The hash to compare against.

        Returns:
            bool: True if the file hashes match, False otherwise.
        """
        decoded = base64.urlsafe_b64decode(given_hash)
        salt_len = 16
        salt = decoded[:salt_len]
        computed_hash = self.hash_file(file_path, temp_salt=salt)
        return computed_hash == given_hash

    def _split_into_blocks(self, data: bytes) -> Generator[bytes, None, None]:
        """
        Splits data into blocks of the specified block size.

        Args:
            data (bytes): The data to be split into blocks.

        Yields:
            bytes: Each block of data.
        """
        for i in range(0, len(data), self.block_size):
            block = data[i:i + self.block_size]
            if len(block) < self.block_size:
                block = block.ljust(self.block_size, b'\0')
            yield block
