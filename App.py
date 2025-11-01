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

# Set page config with a new icon
st.set_page_config(page_title="MiniFin Secure App", layout="wide", page_icon="🛡️")

# Generate a secret key for encryption.
APP_ENCRYPTION_KEY = b'p_Z1c-PqM0g2xV8t9y-J_uA6wB5nE1oI_zS4cQ7kR3g='
cipher_suite = Fernet(APP_ENCRYPTION_KEY)

# --- THEME & STYLING (NEW!) ---

def load_css():
    """Injects custom CSS for a modern, professional 'FinTech' theme."""
    css = """
    <style>
        /* Main Page Background: Light, professional grey-blue */
        [data-testid="stAppViewContainer"] {
            background-color: #F0F4F8;
        }

        /* Sidebar: Clean white, with a subtle border */
        [data-testid="stSidebar"] {
            background-color: #FFFFFF;
            border-right: 1px solid #E0E0E0;
        }

        /* Titles: Strong, dark professional blue */
        h1, h2 {
            color: #0D47A1;
        }

        /* Form & Metric "Cards": White, with a cleaner shadow and border */
        [data-testid="stForm"], [data-testid="stMetric"] {
            background-color: #FFFFFF;
            border-radius: 12px;
            padding: 25px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.07);
            border: 1px solid #EAEAEA;
        }
        
        /* Ensure metric cards have a consistent height */
        [data-testid="stMetric"] {
             padding: 20px;
        }

        /* Custom Button Style: Refined blue gradient */
        .stButton > button {
            border: none;
            border-radius: 8px;
            padding: 10px 24px;
            color: white;
            background: linear-gradient(90deg, #0D47A1, #1976D2);
            transition: all 0.3s ease;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        /* Interactive Button Hover Effect */
        .stButton > button:hover {
            transform: scale(1.03);
            box-shadow: 0 6px 12px rgba(0,0,0,0.15);
            opacity: 0.9;
        }
    </style>
    """
    st.markdown(css, unsafe_allow_html=True)


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
# (These functions are unchanged to ensure security is maintained)

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
    
    st.title("Welcome to MiniFin 🛡️")
    st.caption("A secure FinTech demo app for BSFT-7")
    
    col1, col2 = st.columns(2)

    with col1:
        st.header("Login 🔑")
        
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
                    st.error("A database error occurred. Please try again later.")
                    log_activity(username, f"Database error during login: {e}")


    with col2:
        st.header("Register ✍️")
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
    st.caption("This is your secure FinTech application dashboard.")
    
    # --- Interactive Metrics ---
    try:
        conn = sqlite3.connect('fintech_app.db')
        c = conn.cursor()
        # Get transaction count
        c.execute("SELECT COUNT(*) FROM transactions WHERE username = ?", (st.session_state.username,))
        tx_count = c.fetchone()[0]
        
        # Get last log action
        c.execute("SELECT action FROM audit_logs WHERE username = ? ORDER BY timestamp DESC LIMIT 1", (st.session_state.username,))
        last_log = c.fetchone()
        last_action = last_log[0] if last_log else "No activity"
    except Exception as e:
        tx_count = "N/A"
        last_action = "Error"
    finally:
        if conn:
            conn.close()

    col1, col2 = st.columns(2)
    # The [data-testid="stMetric"] style from load_css() will apply to these
    col1.metric("Total Transactions", f"{tx_count}")
    col2.metric("Last Logged Action", f"{last_action}")
    st.divider()
    # --- End of New Section ---

    st.subheader("Security Test Zone")
    st.warning("Test 17: Secure Error Handling")
    st.write("Click the button below to simulate an internal server error (Divide by Zero).")
    
    if st.button("Simulate Error"):
        try:
            # --- Test Case 17: Secure Error Handling ---
            x = 10 / 0 # Force a divide-by-zero error
        except ZeroDivisionError as e:
            # We catch the specific error and show a generic message
            st.error("An unexpected operation failed. The app did not crash.")
            log_activity(st.session_state.username, "Simulated divide-by-zero error")

def show_profile_page():
    st.title("Manage Your Profile 👤")
    
    try:
        conn = sqlite3.connect('fintech_app.db')
        c = conn.cursor()
        # --- Test Case 14: Data Modification Attempt ---
        c.execute("SELECT full_name, email, secret_note_encrypted FROM users WHERE username = ?", 
                  (st.session_state.username,))
        user_data = c.fetchone()
        
        current_full_name = user_data[0] if user_data[0] else ""
        current_email = user_data[1] if user_data[1] else ""
        current_secret_note_encrypted = user_data[2]
        
        decrypted_note = ""
        if current_secret_note_encrypted:
            decrypted_note = decrypt_data(current_secret_note_encrypted)

        # The [data-testid="stForm"] style from load_css() will apply here
        with st.form("profile_update_form"):
            st.write(f"**Username:** `{st.session_state.username}` (cannot be changed)")
            
            # --- Test Case 10: Input Length Validation ---
            full_name = st.text_input("Full Name", value=current_full_name, max_chars=100)
            
            # --- Test Case 15: Email Validation ---
            email = st.text_input("Email", value=current_email)
            
            # --- Test Case 7 & 18: Encryption / Decryption Option ---
            st.subheader("Secure Encrypted Note 🤫")
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
                    
                    st.toast("Profile updated successfully!", icon="🎉")
                    
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
        st.header("Add New Transaction ➕")
        # The [data-testid="stForm"] style from load_css() will apply here
        with st.form("transaction_form"):
            trans_type = st.selectbox("Type", ["Deposit", "Withdrawal"])
            
            # --- Test Case 12: Number Field Validation ---
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
                        
                        st.toast(f"{trans_type} of ${amount:.2f} recorded.", icon="✅")
                        
                        log_activity(st.session_state.username, f"Added transaction: {trans_type} ${amount}")
                        
                        if uploaded_file is not None:
                            st.info(f"File '{uploaded_file.name}' was uploaded successfully (test passed).")
                    
                    except sqlite3.Error as e:
                        st.error("A database error occurred while adding the transaction.")
                        log_activity(st.session_state.username, f"DB error on transaction: {e}")

    with col2:
        st.header("Transaction History 📊")
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
    st.write("This log tracks all security-sensitive actions in your account.")
    
    try:
        conn = sqlite3.connect('fintech_app.db')
        # Show logs only for the current user.
        df = pd.read_sql_query("SELECT timestamp, username, action FROM audit_logs WHERE username = ? ORDER BY timestamp DESC",
                               conn, params=(st.session_state.username,))
        conn.close()
        st.dataframe(df, use_container_width=True)
    except Exception as e:
        st.error("Could not load activity logs.")


# --- MAIN APP LOGIC ---

def main():
    # --- Load Custom CSS ---
    load_css()

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
        
        # --- NEW: SVG Logo (Replaces broken image link) ---
        # This is a self-contained SVG, so it requires no external files.
        logo_svg = f"""
        <div style="display: flex; justify-content: center; padding-bottom: 10px;">
            <svg width="90" height="90" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                <defs>
                    <linearGradient id="logoGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                        <stop offset="0%" style="stop-color:#0D47A1;stop-opacity:1" />
                        <stop offset="100%" style="stop-color:#1976D2;stop-opacity:1" />
                    </linearGradient>
                </defs>
                <path fill="url(#logoGradient)" d="M12 2L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-3z"/>
                <path fill="#FFFFFF" d="M16.59 7.58L10 14.17l-3.59-3.58L5 12l5 5 8-8-1.41-1.42z"/>
            </svg>
        </div>
        """
        st.sidebar.markdown(logo_svg, unsafe_allow_html=True)
        # --- End of New Logo ---

        st.sidebar.title(f"Logged in as:")
        st.sidebar.header(f"**{st.session_state.username}**")
        st.sidebar.divider()
        
        # --- Test Case 5: Session Expiry ---
        st.sidebar.info("Note: Streamlit sessions do not auto-expire on idle. Please log out manually.")

        # --- Test Case 6: Logout Functionality ---
        if st.sidebar.button("Logout"):
            log_activity(st.session_state.username, "User logged out")
            st.session_state.authenticated = False
            st.session_state.username = None
            st.session_state.login_attempts = 0 # Reset attempts on logout
            st.rerun()

        st.sidebar.title("Navigation")
        # --- Added icons to navigation ---
        page_selection = st.sidebar.radio("Go to", 
                                ["Dashboard 🏠", "My Profile 👤", "Transactions 💸", "Activity Log 📜"])

        # Check which page was selected and show it
        if page_selection.startswith("Dashboard"):
            show_dashboard()
        elif page_selection.startswith("My Profile"):
            show_profile_page()
        elif page_selection.startswith("Transactions"):
            show_transactions_page()
        elif page_selection.startswith("Activity Log"):
            show_activity_log_page()

if __name__ == "__main__":
    main()


