import hashlib
import requests
import time
import logging
import os

# Logging configuration
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

API_URL = "https://api.pwnedpasswords.com/range/"

def hash_password(password):
    
    #Hashes a password using SHA-1 and returns the hash in uppercase.
    
    if not password:
        raise ValueError("Password cannot be empty")
    try:
        logging.debug("Hashing password")
        sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        logging.debug(f"SHA-1 hash: {sha1_hash}")
        return sha1_hash
    except UnicodeEncodeError as e:
        logging.error(f"Error encoding password: {e}")
        raise

def check_password_in_pwned(hash_prefix):
    
    #Queries the Pwned Passwords API with the hash prefix (first 5 characters).
    #Returns a list of hash suffixes and breach counts.
    
    logging.info(f"Querying API with prefix: {hash_prefix}")
    try:
        response = requests.get(API_URL + hash_prefix, timeout=5)
        response.raise_for_status()
        logging.info("Query successful")
        return response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"API access error: {e}")
        raise RuntimeError("Failed to make API request") from e

def is_password_pwned(password):
    
    #Checks if a password exists in the compromised password database.
    
    logging.info(f"Checking password: {password}")
    try:
        sha1_hash = hash_password(password)
        hash_prefix, hash_suffix = sha1_hash[:5], sha1_hash[5:]
        logging.debug(f"Prefix: {hash_prefix}, Suffix: {hash_suffix}")

        pwned_data = check_password_in_pwned(hash_prefix)
        for line in pwned_data.splitlines():
            parts = line.split(":")
            if len(parts) != 2:
                logging.warning(f"Unexpected line format: {line}")
                continue

            suffix, count = parts
            if suffix == hash_suffix:
                logging.info(f"Password found in database: {count} times")
                return True, int(count)

        logging.info("Password not found in database")
        return False, 0
    except ValueError as e:
        logging.error(f"Error processing password: {e}")
        return False, 0

def process_passwords(input_file, output_file):
    
    #Processes a list of passwords from the input file and saves the results.
    
    if not os.path.exists(input_file):
        logging.error(f"File not found: {input_file}")
        return

    logging.info(f"Reading passwords from file: {input_file}")
    try:
        with open(input_file, "r", encoding="utf-8") as file:
            passwords = file.readlines()
    except Exception as e:
        logging.error(f"Error reading file: {e}")
        return

    results = []
    for password in passwords:
        password = password.strip()
        if not password:
            logging.warning("Skipped empty line")
            continue

        try:
            pwned, count = is_password_pwned(password)
            if pwned:
                results.append(f"{password}: Compromised ({count} times)")
            else:
                results.append(f"{password}: Safe")
        except Exception as e:
            logging.error(f"Error checking password: {e}")
            results.append(f"{password}: Error occurred")

        # Add a pause to avoid API blocking
        time.sleep(1)

    logging.info(f"Writing results to file: {output_file}")
    try:
        with open(output_file, "w", encoding="utf-8") as file:
            file.write("\n".join(results))
        logging.info(f"Results saved to {output_file}")
    except IOError as e:
        logging.error(f"File write error: {e}")

def main():
    
    #Main script entry point.
    
    logging.info("Script started")
    input_file = "passwords.txt"  # Input file
    output_file = "results.txt"  # Output file with results
    process_passwords(input_file, output_file)
    logging.info("Script finished")

if __name__ == "__main__":
    main()
