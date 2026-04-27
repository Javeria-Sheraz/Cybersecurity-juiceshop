# Secure User Management System Project

## Project Overview
This project involved securing a mock web application (OWASP Juice Shop) by identifying vulnerabilities and implementing industry-standard security measures.

## Security Implementations
- **SQL Injection Prevention:** Implemented input validation using the `validator` library and parameterized queries to block malicious characters.
- **Secure Password Hashing:** Migrated from MD5 to `bcrypt` for salting and hashing user passwords.
- **HTTP Header Security:** Integrated `Helmet.js` to protect against Clickjacking and XSS.
- **Security Logging:** Set up a centralized logging system using `winston` to track application events in `security.log`.

## How to Run
1. Clone the repository.
2. Run `npm install` to install dependencies.
3. Run `npm start` to launch the secure server.

## Technologies Used
- Node.js / Express
- Bcrypt (Cryptography)
- Helmet.js (Header Security)
- Winston (Logging)
- Validator (Sanitization)
