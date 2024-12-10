import hashlib
import requests
import time
import logging

# Налаштування логування
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

API_URL = "https://api.pwnedpasswords.com/range/"

def hash_password(password):
    """Хешує пароль у формат SHA-1 і повертає хеш."""
    logging.debug("Хешування пароля")
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    logging.debug(f"SHA-1 хеш: {sha1_hash}")
    return sha1_hash

def check_password_in_pwned(hash_prefix):
    """
    Звертається до API Pwned Passwords з префіксом хешу (перші 5 символів).
    Повертає список суфіксів і кількість витоків.
    """
    logging.info(f"Запит до API з префіксом: {hash_prefix}")
    try:
        response = requests.get(API_URL + hash_prefix, timeout=5)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        logging.error(f"Помилка доступу до API: {e}")
        raise RuntimeError("Не вдалося виконати запит до API") from e

    logging.info("Успішний запит до API")
    return response.text

def is_password_pwned(password):
    """Перевіряє, чи пароль є в базі зламаних."""
    logging.info(f"Перевірка пароля: {password}")
    sha1_hash = hash_password(password)
    hash_prefix, hash_suffix = sha1_hash[:5], sha1_hash[5:]
    logging.debug(f"Префікс: {hash_prefix}, Суфікс: {hash_suffix}")

    try:
        pwned_data = check_password_in_pwned(hash_prefix)
    except RuntimeError:
        logging.warning(f"Не вдалося перевірити пароль: {password}")
        return False, 0

    for line in pwned_data.splitlines():
        suffix, count = line.split(":")
        if suffix == hash_suffix:
            logging.info(f"Пароль знайдено у базі: {count} разів")
            return True, int(count)

    logging.info("Пароль не знайдено у базі")
    return False, 0

def process_passwords(input_file, output_file):
    """Обробляє список паролів з вхідного файлу та зберігає результати."""
    logging.info(f"Читання паролів з файлу: {input_file}")
    try:
        with open(input_file, "r") as file:
            passwords = file.readlines()
    except FileNotFoundError:
        logging.error(f"Файл не знайдено: {input_file}")
        return

    results = []
    for password in passwords:
        password = password.strip()
        if not password:
            logging.warning("Пропущено порожній рядок")
            continue

        pwned, count = is_password_pwned(password)
        if pwned:
            results.append(f"{password}: Зламаний ({count} разів)")
        else:
            results.append(f"{password}: Безпечний")

        # Додаємо паузу для уникнення блокування API
        time.sleep(1)

    logging.info(f"Запис результатів у файл: {output_file}")
    try:
        with open(output_file, "w") as file:
            file.write("\n".join(results))
    except IOError as e:
        logging.error(f"Помилка запису у файл: {e}")
        return

    logging.info(f"Результати збережено у {output_file}")

def main():
    """Головна функція запуску скрипта."""
    logging.info("Початок роботи скрипта")
    input_file = "passwords.txt"  # Вхідний файл
    output_file = "results.txt"  # Результат
    process_passwords(input_file, output_file)
    logging.info("Завершення роботи скрипта")

if __name__ == "__main__":
    main()
