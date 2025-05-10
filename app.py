import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import os




# Generate a key (In real systems, securely store and reuse the same key)
# Load a fixed key from environment
KEY = os.environ.get("FERNET_KEY").encode()
cipher = Fernet(KEY)

# Session state setup
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# In-memory data storage
stored_data = {}  # {"ref_name": {"encrypted_text": "xyz", "passkey": "hashed"}}

# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Function to encrypt data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text, passkey, ref_name):
    if ref_name not in stored_data:
        return None

    hashed_passkey = hash_passkey(passkey)
    entry = stored_data[ref_name]

    if entry["passkey"] == hashed_passkey:
        st.session_state.failed_attempts = 0
        return cipher.decrypt(encrypted_text.encode()).decode()

    st.session_state.failed_attempts += 1
    return None

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    ref_name = st.text_input("Enter Reference Name (e.g., MyNote):")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey and ref_name:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            stored_data[ref_name] = {"encrypted_text": encrypted_text, "passkey": hashed_passkey}
            st.success("✅ Data stored securely!")
            st.code(encrypted_text, language="text")
        else:
            st.error("⚠️ All fields are required!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    ref_name = st.text_input("Enter Reference Name:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if ref_name in stored_data:
        encrypted_text = stored_data[ref_name]["encrypted_text"]
    else:
        encrypted_text = ""

    if st.button("Decrypt"):
        if ref_name and passkey:
            decrypted = decrypt_data(encrypted_text, passkey, ref_name)
            if decrypted:
                st.success(f"✅ Decrypted Data: {decrypted}")
            else:
                st.error(f"❌ Incorrect passkey! Attempts left: {3 - st.session_state.failed_attempts}")
                if st.session_state.failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
                    st.experimental_set_query_params(page="Login")
                    st.experimental_rerun()
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":
            st.session_state.failed_attempts = 0
            st.success("✅ Reauthorized. Go back to Retrieve Data.")
        else:
            st.error("❌ Incorrect password!")
