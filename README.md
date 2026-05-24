# Secure User Management System Project

## Project Overview
This project involved securing a mock web application (OWASP Juice Shop) by identifying vulnerabilities and implementing industry-standard security measures across all internship phases.

## Security Implementations
- **SQL Injection Prevention:** Implemented input validation using the `validator` library and parameterized queries to block malicious characters.
- **Secure Password Hashing:** Migrated from MD5 to `bcrypt` for salting and hashing user passwords.
- **HTTP Header Security:** Integrated `Helmet.js` to protect against Clickjacking, XSS, and enforce HSTS transit policies.
- **Security Logging & Monitoring:** Set up a centralized logging system using `winston` to track application events and log real-time failed login intrusion alerts in `security.log`.
- **API Rate Limiting:** Applied `express-rate-limit` on authentication endpoints to mitigate brute-force and credential-stuffing attacks.
- **CSRF Protection:** Integrated `csurf` and `cookie-parser` middleware to block cross-site request forgery state exploits.
- **Compliance Auditing:** Performed automated security composition audits mapping dependencies against the OWASP Top 10 framework.

## How to Run
1. Clone the repository.
2. Run `npm install` to install dependencies.
3. Run `npm start` to launch the secure server.

## Technologies Used
- Node.js / Express
- Bcrypt (Cryptography)
- Helmet.js (Header Security)
- Winston (Logging & Monitoring)
- Validator (Sanitization)
- Express-Rate-Limit (API Throttling)
- Csurf (Anti-CSRF Protection)
