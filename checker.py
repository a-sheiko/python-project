# checker.py
import hashlib
import requests

# Константи
API_URL = "https://api.pwnedpasswords.com/range/"

def hash_password(password):
    """Хешує пароль у формат SHA-1 і повертає хеш."""
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return sha1_hash

def check_password_in_pwned(hash_prefix):
    """
    Звертається до API Pwned Passwords з префіксом хешу (перші 5 символів).
    Повертає список суфіксів і кількість витоків.
    """
    response = requests.get(API_URL + hash_prefix)
    if response.status_code != 200:
        raise RuntimeError(f"Помилка доступу до API: {response.status_code}")
    return response.text

def is_password_pwned(password):
    """Перевіряє, чи пароль є в базі зламаних."""
    sha1_hash = hash_password(password)
    hash_prefix, hash_suffix = sha1_hash[:5], sha1_hash[5:]
    pwned_data = check_password_in_pwned(hash_prefix)
    for line in pwned_data.splitlines():
        suffix, count = line.split(":")
        if suffix == hash_suffix:
            return True, int(count)
    return False, 0

def main(input_file, output_file):
    with open(input_file, "r") as file:
        passwords = file.readlines()

    results = []
    for password in passwords:
        password = password.strip()
        pwned, count = is_password_pwned(password)
        if pwned:
            results.append(f"{password}: Зламаний ({count} разів)")
        else:
            results.append(f"{password}: Безпечний")

    with open(output_file, "w") as file:
        file.write("\n".join(results))

    print(f"Результати збережено у {output_file}")

if __name__ == "__main__":
    input_file = "passwords.txt"  # Вхідний файл
    output_file = "results.txt"  # Результат
    main(input_file, output_file)
