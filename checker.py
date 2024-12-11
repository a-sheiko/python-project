import hashlib
import requests
import time
import logging

# Logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

API_URL = "https://api.pwnedpasswords.com/range/"

def hash_password(password):
    # Hashes a password using SHA-1 and returns the hash
    logging.debug("Hashing password")
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    logging.debug(f"SHA-1 hash: {sha1_hash}")
    return sha1_hash

def check_password_in_pwned(hash_prefix):
    
    # Queries the Pwned Passwords API with the hash prefix (first 5 characters)
    # Returns a list of suffixes and the number of breaches

    logging.info(f"Querying with prefix: {hash_prefix}")
    try:
        response = requests.get(API_URL + hash_prefix, timeout=5)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        logging.error(f"API access error: {e}")
        raise RuntimeError("Failed to make API request") from e

    logging.info(Query successful")
    return response.text

def is_password_pwned(password):
    #Checks if a password exists in the compromised password database
    logging.info(f"Checking password: {password}")
    sha1_hash = hash_password(password)
    hash_prefix, hash_suffix = sha1_hash[:5], sha1_hash[5:]
    logging.debug(f"Prefix: {hash_prefix}, Suffix: {hash_suffix}")

    try:
        pwned_data = check_password_in_pwned(hash_prefix)
    except RuntimeError:
        logging.warning(f"Failed to check password: {password}")
        return False, 0
 
    for line in pwned_data.splitlines():
        suffix, count = line.split(":")
        if suffix == hash_suffix:
            logging.info(f"Password found in database: {count} times")
            return True, int(count)

    logging.info("Password not found in database")
    return False, 0

def process_passwords(input_file, output_file):
    #Processes a list of passwords from the input file and saves the results
    logging.info(f"Reading passwords from file: {input_file}")
    try:
        with open(input_file, "r") as file:
            passwords = file.readlines()
    except FileNotFoundError:
        logging.error(f"File not found: {input_file}")
        return

    results = []
    for password in passwords:
        password = password.strip()
        if not password:
            logging.warning("Skipped empty line")
            continue

        pwned, count = is_password_pwned(password)
        if pwned:
            results.append(f"{password}: Compromised ({count} times)")
        else:
            results.append(f"{password}: Safe")

        # Add a pause to avoid API blocking
        time.sleep(1)

    logging.info(f"Writing results to file: {output_file}")
    try:
        with open(output_file, "w") as file:
            file.write("\n".join(results))
    except IOError as e:
        logging.error(f"File write error: {e}")
        return

    logging.info(f"Results saved to {output_file}")

def main():
    #Main script entry point
    logging.info("Script started")
    input_file = "passwords.txt"  # Input file
    output_file = "results.txt"  # Output file
    process_passwords(input_file, output_file)
    logging.info("Script finished")

if __name__ == "__main__":
    main()
