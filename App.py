# app.py
# Import necessary libraries
import streamlit as st
import sqlite3
import bcrypt  # For password hashing (pip install bcrypt)
import re      # For regex (password/email validation)
import pandas as pd
from cryptography.fernet import Fernet  # For encryption (pip install cryptography)
from datetime import datetime

# --- CONFIG & INITIALIZATION ---

st.set_page_config(page_title="MiniFin Secure App", layout="wide")

# Generate a secret key for encryption. 
# In a real app, this key MUST be stored securely, not in the code.
# For this assignment, we'll define it here.
# You can generate one using: Fernet.generate_key().decode()
APP_ENCRYPTION_KEY = b'p_Z1c-PqM0g2xV8t9y-J_uA6wB5nE1oI_zS4cQ7kR3g='
cipher_suite = Fernet(APP_ENCRYPTION_KEY)

# --- DATABASE SETUP ---

def init_db():
    """Initializes the SQLite database and creates tables if they don't exist."""
    conn = sqlite3.connect('fintech_app.db')
    c = conn.cursor()
    
    # User table with hashed password and encrypted secret
    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        email TEXT,
        full_name TEXT,
        secret_note_encrypted TEXT 
    )
    ''')
    
    # Audit log table
    c.execute('''
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME NOT NULL,
        username TEXT NOT NULL,
        action TEXT NOT NULL
    )
    ''')

    # Transactions table
    c.execute('''
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        type TEXT NOT NULL,
        amount REAL NOT NULL,
        description TEXT,
        FOREIGN KEY (username) REFERENCES users (username)
    )
    ''')
    
    conn.commit()
    conn.close()

# --- HELPER FUNCTIONS (SECURITY & LOGGING) ---

def hash_password(password):
    """Hashes a password using bcrypt."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(password, hashed):
    """Checks if a password matches its hash."""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed)
    except (ValueError, TypeError):
        return False

def is_strong_password(password):
    """Validates password strength (min 8 chars, 1 upper, 1 lower, 1 digit, 1 symbol)."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain a lowercase letter."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain an uppercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain a digit."
    if not re.search(r"[!@#$%^&*(),.?:{}|<>]", password):
        return False, "Password must contain a special symbol."
    return True, "Password is strong."

def is_valid_email(email):
    """Simple email regex validation."""
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

def log_activity(username, action):
    """Logs a user action to the audit_logs table."""
    try:
        conn = sqlite3.connect('fintech_app.db')
        c = conn.cursor()
        c.execute("INSERT INTO audit_logs (timestamp, username, action) VALUES (?, ?, ?)",
                  (datetime.now(), username, action))
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        st.warning(f"Failed to log activity: {e}") # Non-critical error

def encrypt_data(data):
    """Encrypts data using the app key."""
    return cipher_suite.encrypt(data.encode('utf-8'))

def decrypt_data(encrypted_data):
    """Decrypts data using the app key."""
    try:
        return cipher_suite.decrypt(encrypted_data).decode('utf-8')
    except Exception:
        return "Failed to decrypt (data may be corrupted or key is wrong)"

# --- PAGE FUNCTIONS ---

def show_login_page():
    """Displays the login and registration forms."""
    
    st.title("Welcome to MiniFin 🔒")
    
    col1, col2 = st.columns(2)

    with col1:
        st.header("Login")
        
        # Check for login attempts
        if 'login_attempts' not in st.session_state:
            st.session_state.login_attempts = 0
            
        if st.session_state.login_attempts >= 5:
            st.error("Too many failed login attempts. Your account is temporarily locked.")
            return

        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            login_button = st.form_submit_button("Login")

            if login_button:
                # --- Test Case 1: SQL Injection ---
                # This query is parameterized (uses ?), which PREVENTS SQL Injection.
                # Entering ' OR 1=1-- will NOT work.
                try:
                    conn = sqlite3.connect('fintech_app.db')
                    c = conn.cursor()
                    c.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
                    user_data = c.fetchone()
                    conn.close()

                    if user_data and check_password(password, user_data[0]):
                        st.success("Login Successful!")
                        st.session_state.authenticated = True
                        st.session_state.username = username
                        st.session_state.login_attempts = 0 # Reset on success
                        log_activity(username, "User logged in")
                        st.rerun() # Rerun to show the main app
                    else:
                        st.session_state.login_attempts += 1
                        log_activity(username, f"Failed login attempt ({st.session_state.login_attempts})")
                        st.error("Invalid username or password.")
                
                # --- Test Case 9: Error Message Leakage ---
                except sqlite3.Error as e:
                    # We show a generic error, not the specific SQL error (e)
                    st.error("A database error occurred. Please try again later.")
                    log_activity(username, f"Database error during login: {e}")


    with col2:
        st.header("Register")
        with st.form("register_form"):
            reg_username = st.text_input("Choose Username")
            reg_email = st.text_input("Email")
            reg_password = st.text_input("Create Password", type="password")
            reg_confirm_password = st.text_input("Confirm Password", type="password")
            register_button = st.form_submit_button("Register")

            if register_button:
                # --- Test Case 20: Empty Field Submission ---
                if not reg_username or not reg_password or not reg_confirm_password or not reg_email:
                    st.warning("All fields are required.")
                
                # --- Test Case 13: Password Match Check ---
                elif reg_password != reg_confirm_password:
                    st.warning("Passwords do not match.")
                
                # --- Test Case 2: Password Strength ---
                elif not is_strong_password(reg_password)[0]:
                    st.warning(f"Password is not strong: {is_strong_password(reg_password)[1]}")
                
                # --- Test Case 15: Email Validation ---
                elif not is_valid_email(reg_email):
                    st.warning("Please enter a valid email address.")
                
                else:
                    try:
                        conn = sqlite3.connect('fintech_app.db')
                        c = conn.cursor()
                        
                        # --- Test Case 11: Duplicate User Registration ---
                        c.execute("SELECT id FROM users WHERE username = ?", (reg_username,))
                        if c.fetchone():
                            st.warning("Username already exists. Please choose another one.")
                        else:
                            hashed_pass = hash_password(reg_password)
                            c.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                                      (reg_username, hashed_pass, reg_email))
                            conn.commit()
                            st.success("Registration successful! You can now log in.")
                            log_activity(reg_username, "User registered")
                    
                    # --- Test Case 9: Error Message Leakage ---
                    except sqlite3.Error as e:
                        st.error("A database error occurred during registration.")
                        log_activity(reg_username, f"Database error during registration: {e}")
                    finally:
                        conn.close()

def show_dashboard():
    st.title(f"Welcome to your Dashboard, {st.session_state.username}! 👋")
    st.write("This is your secure FinTech application dashboard.")
    
    st.subheader("Quick Actions")
    st.info("Use the navigation on the left to manage your profile, view transactions, or see activity logs.")

    st.subheader("Security Test Zone")
    st.warning("Test 17: Secure Error Handling")
    st.write("Click the button below to simulate an internal server error (Divide by Zero).")
    
    if st.button("Simulate Error"):
        try:
            # --- Test Case 17: Secure Error Handling ---
            x = 10 / 0 # Force a divide-by-zero error
        except ZeroDivisionError as e:
            # We catch the specific error and show a generic message,
            # not the stack trace.
            st.error("An unexpected operation failed. The app did not crash.")
            log_activity(st.session_state.username, "Simulated divide-by-zero error")

def show_profile_page():
    st.title("Manage Your Profile 👤")
    
    try:
        conn = sqlite3.connect('fintech_app.db')
        c = conn.cursor()
        # --- Test Case 14: Data Modification Attempt ---
        # We fetch data ONLY for the logged-in user, preventing Insecure Direct Object Reference (IDOR)
        c.execute("SELECT full_name, email, secret_note_encrypted FROM users WHERE username = ?", 
                  (st.session_state.username,))
        user_data = c.fetchone()
        
        current_full_name = user_data[0] if user_data[0] else ""
        current_email = user_data[1] if user_data[1] else ""
        current_secret_note_encrypted = user_data[2]
        
        decrypted_note = ""
        if current_secret_note_encrypted:
            decrypted_note = decrypt_data(current_secret_note_encrypted)

        with st.form("profile_update_form"):
            st.write(f"**Username:** `{st.session_state.username}` (cannot be changed)")
            
            # --- Test Case 10: Input Length Validation ---
            full_name = st.text_input("Full Name", value=current_full_name, max_chars=100)
            
            # --- Test Case 15: Email Validation ---
            email = st.text_input("Email", value=current_email)
            
            # --- Test Case 7 & 18: Encryption / Decryption Option ---
            st.subheader("Secure Encrypted Note")
            st.write("This data is stored encrypted in the database.")
            secret_note = st.text_area("Your Secret Note", value=decrypted_note)
            
            update_button = st.form_submit_button("Update Profile")

            if update_button:
                if not is_valid_email(email):
                    st.warning("Please enter a valid email address.")
                else:
                    encrypted_note_to_save = encrypt_data(secret_note)
                    c.execute("""
                        UPDATE users 
                        SET full_name = ?, email = ?, secret_note_encrypted = ?
                        WHERE username = ? 
                    """, (full_name, email, encrypted_note_to_save, st.session_state.username))
                    conn.commit()
                    st.success("Profile updated successfully!")
                    log_activity(st.session_state.username, "User updated profile")
                    
                    # --- Test Case 3: Special Character Input (XSS) ---
                    st.subheader("Testing Cross-Site Scripting (XSS):")
                    st.write("If you entered `<script>alert(1)</script>` in your name, you should see the *text* below, not an alert box. Streamlit auto-sanitizes this output.")
                    st.markdown(f"**Updated Name Displayed:** {full_name}")

        conn.close()

    except sqlite3.Error as e:
        st.error("A database error occurred.")
        log_activity(st.session_state.username, f"Database error on profile page: {e}")


def show_transactions_page():
    st.title("My Transactions 💸")

    col1, col2 = st.columns([1, 2])

    with col1:
        st.header("Add New Transaction")
        with st.form("transaction_form"):
            trans_type = st.selectbox("Type", ["Deposit", "Withdrawal"])
            
            # --- Test Case 12: Number Field Validation ---
            # st.number_input automatically rejects non-numeric characters.
            amount = st.number_input("Amount", min_value=0.01, format="%.2f")
            
            # --- Test Case 19: Input Encoding (Emoji) ---
            description = st.text_area("Description (Try using Emojis! 😊)")
            
            # --- Test Case 8: File Upload Validation ---
            st.subheader("Upload Receipt (Optional)")
            uploaded_file = st.file_uploader(
                "Only PDF, PNG, or JPG allowed",
                type=["pdf", "png", "jpg", "jpeg"]
            )
            
            add_button = st.form_submit_button("Add Transaction")

            if add_button:
                if not amount or not description:
                    st.warning("Please fill in all transaction details.")
                else:
                    try:
                        conn = sqlite3.connect('fintech_app.db')
                        c = conn.cursor()
                        c.execute("INSERT INTO transactions (username, type, amount, description) VALUES (?, ?, ?, ?)",
                                  (st.session_state.username, trans_type, amount, description))
                        conn.commit()
                        conn.close()
                        st.success(f"{trans_type} of ${amount:.2f} recorded.")
                        log_activity(st.session_state.username, f"Added transaction: {trans_type} ${amount}")
                        
                        if uploaded_file is not None:
                            st.info(f"File '{uploaded_file.name}' was uploaded successfully (test passed).")
                    
                    except sqlite3.Error as e:
                        st.error("A database error occurred while adding the transaction.")
                        log_activity(st.session_state.username, f"DB error on transaction: {e}")

    with col2:
        st.header("Transaction History")
        try:
            conn = sqlite3.connect('fintech_app.db')
            # Load transactions only for the logged-in user
            df = pd.read_sql_query("SELECT type, amount, description FROM transactions WHERE username = ?", 
                                   conn, params=(st.session_state.username,))
            conn.close()
            st.dataframe(df, use_container_width=True)
        except Exception as e:
            st.error("Could not load transaction history.")
            log_activity(st.session_state.username, f"Error loading history: {e}")

def show_activity_log_page():
    st.title("Audit & Activity Logs 📜")
    st.write("This log tracks all security-sensitive actions in the application.")
    
    try:
        conn = sqlite3.connect('fintech_app.db')
        # In a real app, only an ADMIN should see all logs.
        # For this assignment, we show logs for the current user.
        df = pd.read_sql_query("SELECT timestamp, username, action FROM audit_logs WHERE username = ? ORDER BY timestamp DESC",
                               conn, params=(st.session_state.username,))
        conn.close()
        st.dataframe(df, use_container_width=True)
    except Exception as e:
        st.error("Could not load activity logs.")


# --- MAIN APP LOGIC ---

def main():
    # Initialize the database
    init_db()

    # Initialize session state for authentication
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False

    # --- Test Case 4: Unauthorized Access ---
    if not st.session_state.authenticated:
        # If user is not logged in, show the login page
        show_login_page()
    else:
        # If user is logged in, show the main app
        st.sidebar.title(f"Logged in as: **{st.session_state.username}**")
        st.sidebar.image("https://i.imgur.com/v801b6n.png", width=100) # A generic logo
        
        # --- Test Case 5: Session Expiry ---
        # Streamlit's session_state doesn't expire on idle by default.
        # This is a known limitation. We add a note and a manual logout.
        st.sidebar.info("Note: Streamlit sessions do not auto-expire on idle. Please log out manually.")

        # --- Test Case 6: Logout Functionality ---
        if st.sidebar.button("Logout"):
            log_activity(st.session_state.username, "User logged out")
            st.session_state.authenticated = False
            st.session_state.username = None
            st.session_state.login_attempts = 0 # Reset attempts on logout
            st.rerun()

        st.sidebar.title("Navigation")
        page = st.sidebar.radio("Go to", 
                                ["Dashboard", "My Profile", "Transactions", "Activity Log"])

        if page == "Dashboard":
            show_dashboard()
        elif page == "My Profile":
            show_profile_page()
        elif page == "Transactions":
            show_transactions_page()
        elif page == "Activity Log":
            show_activity_log_page()

if __name__ == "__main__":
    main()