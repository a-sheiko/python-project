# Project. Broken Password Checker

Ціль проєкту є перевірка списоку паролів на наявність у базі зламаних паролів за допомогою ресурсу [Have I Been Pwned API](https://haveibeenpwned.com).

## Можливості
- Автоматичне хешування паролів за допомогою SHA-1.
- Перевірка кожного пароля через API.
- Генерація звіту з результатами перевірки.

## Структура проєкту
```
broken-password-checker/
├── checker.py          # Основний код
├── passwords.txt       # Вхідний файл зі списком паролів
├── results.txt         # Результати перевірки
├── requirements.txt    # Залежності для Python
├── README.md           # Документація для користувача
```

## Як встановити

1. Клонувати репозиторій:
   ```bash
   git clone https://github.com/a-sheiko/python-project.git
   cd python-project
   ```

2. Встановити залежності:
   ```bash
   pip install -r requirements.txt
   ```

3. Додати паролі у файл `passwords.txt`. Кожен пароль — на новому рядку.

## Як запустити

Запустіть скрипт:
```bash
python checker.py


Результати будуть збережені у файлі `results.txt`.

## Формат результатів
``
123: Зламаний (1784154 разів)
admin: Зламаний (1786431 разів)
admin123: Зламаний (233673 разів)
637e6b91ac36fb22d0f08d3401da91b3: Безпечний


## Залежності
``
- Python 3.8+
- requests==2.28.2

## Примітки
- Паролі не передаються повністю в API завдяки використанню методу **K-Anonymity**.
- Якщо API не доступне, скрипт виведе помилку під час виконання.
