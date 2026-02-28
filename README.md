# MeetingIQ — AI-Powered Meeting Archive with Security Monitoring

MeetingIQ is a Flask web application that serves as an internal meeting archive with a built-in AI security layer. It uses a Random Forest classifier to detect and log SQL injection and XSS attack attempts in real time.

---

## Features

- Secure login with hashed passwords (scrypt via werkzeug)
- Active/inactive user accounts — inactive accounts are silently blocked
- Meeting archive with search and pagination
- AI-powered attack detection (SQLi and XSS classification)
- Attack log dashboard showing detected threats, confidence scores, and attack type
- Calendar view (2026 / 2027 / 2028)
- Honeypot behaviour: attackers receive a fake 500 error while the attempt is logged silently

---

## Project Structure

```
ai-bouncer/
├── app.py              # Flask application
├── brain.py            # AI security engine (Random Forest classifier)
├── setup_users.py      # CLI tool to manage users in the database
├── requirements.txt    # Python dependencies
└── templates/
    ├── login.html
    ├── signup.html
    ├── index.html
    ├── attacks.html
    ├── calendar.html
    └── error.html
```

The database file `honeypot.db` is created automatically on first run. It is excluded from version control.

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/your-username/ai-bouncer.git
cd ai-bouncer
```

### 2. Create and activate a virtual environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

## Setting Up Users (Required Before First Run)

The application does not include any pre-seeded users. You must create at least one active user before you can log in.

Use `setup_users.py` to manage users:

### Add a user (active — can log in immediately)

```bash
python setup_users.py add <username> <email> <password> --active
```

Example:

```bash
python setup_users.py add johndoe john@example.com StrongPass@1 --active
```

### Add a user (inactive — blocked from logging in)

```bash
python setup_users.py add janedoe jane@example.com StrongPass@2
```

### List all users

```bash
python setup_users.py list
```

### Activate a user

```bash
python setup_users.py activate <username>
```

### Deactivate a user

```bash
python setup_users.py deactivate <username>
```

### Delete a user

```bash
python setup_users.py delete <username>
```

---

## Running the Application

After creating at least one active user, start the Flask server:

```bash
python app.py
```

Then open your browser and go to:

```
http://127.0.0.1:5000
```

---

## How the AI Works

The security engine in `brain.py` uses a **Random Forest classifier** (200 decision trees) trained on:

- 30 benign meeting notes
- 30 SQL injection payloads
- 30 XSS payloads

Each input is converted into a 13-dimensional numeric feature vector covering special character density, SQL/XSS keyword frequency, presence of encoding patterns, and more. The classifier votes across all 200 trees to produce a label (benign or malicious) and a confidence score.

Attack type (SQLi vs XSS) is determined by keyword scoring after the input is flagged as malicious.

---

## Routes

| Route | Description |
|---|---|
| `/` | Meeting archive (requires login) |
| `/login` | Login page |
| `/logout` | Log out and clear session |
| `/attacks` | Attack log dashboard (requires login) |
| `/calendar` | Calendar view (requires login) |

---

## Dependencies

- Flask >= 3.0.0
- scikit-learn >= 1.4.0
- numpy >= 1.26.0
- werkzeug (included with Flask)

---

## Notes

- `honeypot.db` is auto-created on first run and excluded from Git via `.gitignore`
- Passwords are stored as scrypt hashes, never in plain text
- Inactive users receive the same error message as wrong credentials to avoid leaking information
- The `setup_users.py` script should be kept private or deleted after initial setup
