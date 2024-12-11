# Project: Broken Password Checker

## Description
This project is designed to check a list of passwords against a database of compromised passwords using the [Have I Been Pwned API](https://haveibeenpwned.com).

## Features
- Automatic hashing of passwords using SHA-1.
- Checking each password through the API.
- Generating a report with the results of the check.

## Project Structure
```
python-project/
├── checker.py          # Main code
├── passwords.txt       # Input file with a list of passwords
├── results.txt         # Check results
├── requirements.txt    # Python dependencies
├── README.md           # User documentation
```

## How to Install

1. Clone the repository:
   ```bash
   git clone https://github.com/a-sheiko/python-project.git
   cd python-project
   ```

2. Install the dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Add passwords to the `passwords.txt` file. Each password should be on a new line.

## How to Run

Run the script:
```bash
python checker.py
```

The results will be saved in the `results.txt` file.

## Results Format
```
123: Compromised (1,784,154 times)
admin: Compromised (1,786,431 times)
admin123: Compromised (233,673 times)
securepassword: Safe
```

## Dependencies
- Python 3.8+
- requests==2.28.2

## Notes
- Passwords are not fully transmitted to the API thanks to the **K-Anonymity** method.
- If the API is unavailable, the script will output an error during execution.

For additional information about the API functionality, refer to the [HIBP API documentation](https://haveibeenpwned.com/API/v3).

