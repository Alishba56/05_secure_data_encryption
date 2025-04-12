import streamlit as st
import hashlib
import uuid
from cryptography.fernet import Fernet

# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Function to encrypt data
def encrypt_data(text, cipher_suite):
    return cipher_suite.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(data_id, passkey, stored_data, cipher_suite):
    if data_id in stored_data:
        data_entry = stored_data[data_id]
        hashed_passkey = hash_passkey(passkey)
        
        if data_entry["passkey"] == hashed_passkey:
            encrypted_text = data_entry["encrypted_text"]
            return cipher_suite.decrypt(encrypted_text.encode()).decode()
    
    return None

# Initialize session state
def init_session_state():
    if 'failed_attempts' not in st.session_state:
        st.session_state.failed_attempts = 0
    if 'stored_data' not in st.session_state:
        st.session_state.stored_data = {}
    if 'current_page' not in st.session_state:
        st.session_state.current_page = "Home"
    if 'cipher_suite' not in st.session_state:
        KEY = Fernet.generate_key()
        st.session_state.cipher_suite = Fernet(KEY)

# Home page
def show_home():
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")
    
    st.info("""
    ### How to use this system:
    1. Go to **Store Data** to encrypt and save your information
    2. You'll receive a unique Data ID after storing
    3. Use the Data ID and your passkey to retrieve your data
    4. After 3 failed attempts, you'll need to reauthorize
    """)

# Store data page
def show_store_data():
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            # Generate a unique ID for this data entry
            data_id = str(uuid.uuid4())
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data, st.session_state.cipher_suite)
            
            # Store the data
            st.session_state.stored_data[data_id] = {
                "encrypted_text": encrypted_text, 
                "passkey": hashed_passkey
            }
            
            st.success("✅ Data stored securely!")
            st.info(f"Your Data ID: **{data_id}**")
            st.warning("⚠️ Please save this Data ID. You'll need it to retrieve your data.")
        else:
            st.error("⚠️ Both fields are required!")

# Retrieve data page
def show_retrieve_data():
    st.subheader("🔍 Retrieve Your Data")
    data_id = st.text_input("Enter Data ID:")
    passkey = st.text_input("Enter Passkey:", type="password")

    # Display remaining attempts
    attempts_remaining = 3 - st.session_state.failed_attempts
    st.info(f"Attempts remaining: {attempts_remaining}")

    if st.button("Decrypt"):
        if data_id and passkey:
            if data_id in st.session_state.stored_data:
                decrypted_text = decrypt_data(
                    data_id, 
                    passkey, 
                    st.session_state.stored_data, 
                    st.session_state.cipher_suite
                )

                if decrypted_text:
                    st.success("✅ Decryption successful!")
                    st.code(decrypted_text, language="text")
                    st.session_state.failed_attempts = 0
                else:
                    st.session_state.failed_attempts += 1
                    st.error(f"❌ Incorrect passkey! Attempts remaining: {3 - st.session_state.failed_attempts}")

                    if st.session_state.failed_attempts >= 3:
                        st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
                        st.session_state.current_page = "Login"
                        st.rerun()  # Updated from experimental_rerun
            else:
                st.error("❌ Data ID not found!")
        else:
            st.error("⚠️ Both fields are required!")

# Login page
def show_login():
    st.subheader("🔑 Reauthorization Required")
    st.write("You've had too many failed attempts. Please reauthorize to continue.")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # Hardcoded for demo
            st.session_state.failed_attempts = 0
            st.success("✅ Reauthorized successfully! Redirecting to Retrieve Data...")
            st.session_state.current_page = "Retrieve Data"
            st.rerun()  # Updated from experimental_rerun
        else:
            st.error("❌ Incorrect password!")

def main():
    # Initialize session state
    init_session_state()
    
    # App title
    st.title("🔒 Secure Data Encryption System")
    
    # Navigation
    menu = ["Home", "Store Data", "Retrieve Data", "Login"]
    choice = st.sidebar.selectbox("Navigation", menu, index=menu.index(st.session_state.current_page))
    
    # Force redirect to login if too many failed attempts
    if st.session_state.failed_attempts >= 3 and choice != "Login":
        st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
        st.session_state.current_page = "Login"
        choice = "Login"
    else:
        st.session_state.current_page = choice
    
    # Display the appropriate page based on navigation choice
    if choice == "Home":
        show_home()
    elif choice == "Store Data":
        show_store_data()
    elif choice == "Retrieve Data":
        show_retrieve_data()
    elif choice == "Login":
        show_login()

# Entry point of the application
if __name__ == "__main__":
    main()