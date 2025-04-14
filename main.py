

import streamlit as st
import json
import os
import base64
from cryptography.fernet import Fernet
import hashlib
import time

DATA_FILE = "secure_data.json"
KEY_FILE = "fernet_key.key"

# session state default
if "login" not in st.session_state:
    st.session_state.login = False
if "attempts" not in st.session_state:
    st.session_state.attempts = 0
if "current_user" not in st.session_state:
    st.session_state.current_user = None

# Generate or load fernet key
def load_fernet_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    
    else:
        with open(KEY_FILE,"rb") as f:
            key = f.read()
        
    return Fernet(key)

fernet = load_fernet_key()

# Load JSON data

def load_data():
    if not os.path.exists(DATA_FILE):
        return {}
    with open(DATA_FILE,"r") as f:
        return json.load(f)
    
# save json data
def save_data(data):
    with open(DATA_FILE,'w') as f:
        json.dump(data,f)

# PBKDF2 hashing
def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac("sha256",password.encode(),salt, 100000)
    return base64.b64encode(salt + hashed).decode()

def verify_password(stored, provided_password):
    stored_bytes = base64.b64decode(stored.encode())
    salt = stored_bytes[:16]
    stored_hash = stored_bytes[16:]
    new_hash = hashlib.pbkdf2_hmac("sha256",provided_password.encode(),salt,100000)
    return new_hash == stored_hash

# UI pages
def login_page():
    st.title("🔐 Login")

    col1 , col2 = st.columns(2)

    with col1:

         username = st.text_input("Username")
        
    with col2:
       password = st.text_input("password",type='password')

    data = load_data()

    if st.button("Login"):
        if username in data and verify_password(data[username]['passkey'],password):
            st.session_state.login = True
            st.session_state.attempts = 0
            st.session_state.current_user = username
            st.success("Logged in successfully!")
            st.session_state.page = 'home'
            st.rerun()
        else:
            st.error("Invalid Credentials!")

# this part belong to login logic
st.markdown('---')
if st.button("New user? Register here"):
    st.session_state.page = "register"
    st.rerun()

def home_page():
    st.title("🏠 Home Page")
    if st.button("➕ Insert Data"):
         st.session_state.page = "insert"
    if st.button("🔓 Retrieve Data"):
        st.session_state.page = "retrieve"

def insert_data_page():
    st.title("🔒 Store Secure Data")
    data = st.text_area("Enter your data")
    passkey = st.text_input("Enter a secret passkey", type='password')

    if st.button("Encrypt and Save"):
        encrypted = fernet.encrypt(data.encode()).decode()
        user = st.session_state.current_user
        user_data = load_data()
        user_data[user]['encrypted_text'] = encrypted
        user_data[user]['passkey'] = hash_password(passkey)
        save_data(user_data)
        st.success("Data securely saved!")

def retrieve_data_page():
    st.title("🔓 Retrieve Data")
    passkey = st.text_input("Enter your passkey", type='password')
    user = st.session_state.current_user 
    user_data = load_data()

    if st.button("Decrypt"):
        if user in user_data and verify_password(user_data[user]['passkey'], passkey):
            decrypted = fernet.decrypt(user_data[user]["encrypted text"].encode()).decode()
            st.success("Decrypted Data:")
            st.code(decrypted)
            st.session_state.attempts = 0
        
        else:
            st.session_state.attempts += 1
            st.error(f"Wrong passkey! Attempts: {st.session_state.attempts}")
            if st.session_state.attempts >= 3:
                st.session_state.login = False
                st.session_state.page = "login"
                st.warning("Too many failed attempts. Redirecting to login")
                time.sleep(2)
                st.experimental_rerun()

def register_user():
    st.title("📝 Register")
    username = st.text_input("Choose a username")
    password = st.text_input("Choose a password", type='password')

    if st.button("Register"):
        data = load_data()
        if username in data:
            st.warning("User already exists")
        else:
            data[username] = {'passkey': hash_password(password),'encrypted_text': ""}
            save_data(data)
            st.success("User registered successfully! You can now login.")
            st.session_state.page = 'login'
            st.rerun()

    st.markdown('---')
    if st.button("Already registered? Login here"):
        st.session_state.page = 'login'
        st.rerun()


# Main controller

def main():
    if "page" not in st.session_state:
        st.session_state.page = "login"

   # Sidebar navigation
    st.sidebar.title("🔍 Navigate")
    page = st.sidebar.radio("Go to",["Home","Login","Register","Insert Data","Retrieve Data",""])

    
    if not st.session_state.login:
        if st.session_state.page == "login":
            login_page()
        elif st.session_state.page == 'register':
            register_user()

        else:
            register_user()

    else:
        if st.session_state.page == "home":
            home_page()
        elif st.session_state.page == "insert":
            insert_data_page()
        elif st.session_state.page == "retrieve":
            retrieve_data_page()

        if st.button("Logout"):
            st.session_state.login == False
            st.session_state.current_user = None
            st.session_state.page = "login"
            st.success("Logged out.")
            st.rerun()

main()



