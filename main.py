import hashlib
import sys

def identify_hash_algorithm(hash_str):
    # List of supported hashing algorithms
    algorithms = [
        hashlib.md5,
        hashlib.sha1,
        hashlib.sha224,
        hashlib.sha256,
        hashlib.sha384,
        hashlib.sha512,
        hashlib.blake2b,
        hashlib.blake2s,
        hashlib.sha3_224,
        hashlib.sha3_256,
        hashlib.sha3_384,
        hashlib.sha3_512,
        hashlib.shake_128,
        hashlib.shake_256,
        "blowfish",
        # Add more Hashcat-supported algorithms below
        "md4",
        "md5(md5($pass))",
        "md5(md5($salt).$pass)",
        "md5($pass.$salt)",
        "md5($salt.$pass)",
        "md5($salt.$pass.$salt)",
        "md5($salt.md5($pass))",
        "md5($salt.md5($pass.$salt))",
        "md5($salt.md5($salt.$pass))",
        "md5($salt.md5($salt.$pass.$salt))",
        "md5($salt.sha1($pass))",
        # Add more as needed
    ]

    for algorithm in algorithms:
        if algorithm == "blowfish":
            # Blowfish is a symmetric cipher, not a hash function.
            # So, we return "Blowfish" directly.
            return "Blowfish"

        try:
            # Attempt to decode the hash using the current algorithm
            if callable(algorithm):
                decoded_hash = algorithm(hash_str.encode()).hexdigest()
            else:
                decoded_hash = algorithm(bytes.fromhex(hash_str)).hexdigest()

            # If decoding is successful, return the algorithm's name
            if decoded_hash == hash_str.lower():
                return algorithm().name
        except Exception as e:
            # Continue to the next algorithm if decoding fails
            continue

    # Return None if no matching algorithm is found
    return None

def hash_identify(input_data):
    if len(input_data) == 0:
        print("Error: Input data is empty.")
        return

    # If input_data is a file, read hashes from the file
    if input_data.endswith(".txt"):
        try:
            with open(input_data, "r") as file:
                hashes = [line.strip() for line in file]
        except FileNotFoundError:
            print(f"Error: File '{input_data}' not found.")
            return
    else:
        # If input_data is a single hash string
        hashes = [input_data]

    for hash_str in hashes:
        algorithm = identify_hash_algorithm(hash_str)
        if algorithm:
            print(f"Hash: {hash_str} | Algorithm: {algorithm}")
        else:
            print(f"Hash: {hash_str} | Algorithm: Unknown")

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] in ['-h', '--help']:
        print("Usage: python hashIdentifier.py <hash_string_or_file_path>")
        print("\nOptions:")
        print("  <hash_string_or_file_path> : Provide either a hash string or a file path containing hashes.")
        print("  -h, --help                : Show this help message.")
    else:
        input_data = sys.argv[1]
        hash_identify(input_data)
