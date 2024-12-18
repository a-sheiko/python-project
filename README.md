# Project: Broken Password Checker

## Description
This project is designed to check a list of passwords against a database of compromised passwords using the https://haveibeenpwned.com

## Features
- Automatic hashing of passwords using SHA-1
- Checking each password through the API
- Generating a report with the results of the check

## Project Structure
```
python-project/
- checker.py          # Main code
- passwords.txt       # Input file with a list of passwords
- results.txt         # Check results
- requirements.txt    # Python dependencies
- README.md           # User documentation
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

## Results 
```
123: Compromised (1784154 times)
admin: Compromised (1786431 times)
admin123: Compromised (233673 times)
637e6b91ac36fb22d0f08d3401da91b3: Safe
```


