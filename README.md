# Secure FinTech App (BSFT Assignment 2)

This repository contains a mini FinTech application built with Streamlit and Python. It was developed for the **BSFT - 7th Semester (Fall 2025)** course assignment: "Secure FinTech App Development & Manual Cybersecurity Testing," instructed by Dr. Usama Arshad.

The primary objective of this project is to demonstrate the practical implementation of fundamental cybersecurity principles within a functional application, which is then verified through manual security testing.

## 🔒 Implemented Security Features

The application was built with the following security features as required by the assignment:

* **User Authentication:** Secure registration and login system.
* **Password Hashing:** Passwords are never stored in plaintext. They are hashed using **bcrypt**.
* **Strong Password Validation:** Enforces complex password rules (length, upper, lower, digit, symbol) during registration.
* **Input Validation:**
    * Sanitizes user inputs to prevent **Cross-Site Scripting (XSS)**.
    * Uses parameterized SQL queries to prevent **SQL Injection**.
    * Validates input types (e.g., numeric-only for amounts) and length.
* **Session Management:** Secure login, logout, and page protection to prevent unauthorized access.
* **Data Encryption:** Sensitive user data (like the "Secure Note") is encrypted in the database using the **Fernet** (cryptography) library.
* **Secure Error Handling:** Prevents leaking sensitive information (like stack traces) to the user.
* **Audit Logging:** Tracks security-sensitive user actions (login, logout, profile update).
* **File Upload Validation:** Restricts file uploads to specific safe types (PDF, PNG, JPG).
* **Access Control:** Prevents Insecure Direct Object Reference (IDOR) by ensuring users can only access their own data.
* **Login Attempt Lockout:** Locks out users after 5 consecutive failed login attempts.

## 🛠️ Technologies Used

* **Language:** Python
* **Framework:** Streamlit
* **Database:** SQLite 3
* **Security Libraries:** `bcrypt` (hashing), `cryptography` (encryption)
* **Data Display:** `pandas`

## 🚀 How to Run the Application

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/YOUR_USERNAME/YOUR_REPOSITORY_NAME.git](https://github.com/YOUR_USERNAME/YOUR_REPOSITORY_NAME.git)
    cd YOUR_REPOSITORY_NAME
    ```

2.  **(Optional but Recommended) Create a virtual environment:**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3.  **Install the required packages:**
    (Make sure the `requirements.txt` file is in your folder)
    ```bash
    pip install -r requirements.txt
    ```

4.  **Run the Streamlit app:**
    ```bash
    streamlit run app.py
    ```

The application will automatically open in your web browser (e.g., `http://localhost:8501`). The `fintech_app.db` database file will be created in the directory as soon as you interact with the app.

## 🧪 Manual Cybersecurity Testing

As part of the assignment, **20 manual cybersecurity tests** were designed and executed on this application. These tests cover all the features listed above, including SQL Injection, XSS, password strength, unauthorized access, and data encryption.

The detailed test case documentation (Word/Excel file with screenshots) is submitted separately via Google Classroom as per the assignment requirements.

---

## 👤 Author

* **Name:** Sumbal Murtaza
* **Roll No:** 22I-2274
* **Course:** Cybersecurity_BSFT - 7th Semester
