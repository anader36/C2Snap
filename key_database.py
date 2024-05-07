#Importing the necessary libraries
import base64
import sqlite3
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from argon2 import PasswordHasher
from getpass import getpass 
from datetime import datetime
import key_database

# This function converts any given file path into an absolute path.
def normalize_path(path):
    return os.path.abspath(path)

# The filename for the SQLite database where private keys and password hashes are stored.
DATABASE_FILENAME = "key_database.db"

# Generates a random salt for use in key derivation. This adds an extra layer of security.
def generate_key_derivation_salt():
    return os.urandom(16)

# Encrypts a private key using a password and a salt, returning the encrypted key.
def encrypt_private_key(private_key, password, salt):
    # Set up a key derivation function with specified parameters.
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000 
    )
    # Derive a secure key from the password and use it to initialize a Fernet cipher object.
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    cipher = Fernet(key)
    return cipher.encrypt(private_key.encode())

# Decrypts an encrypted private key using a password and a salt, returning the decrypted key.
def decrypt_private_key(encrypted_key, password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    cipher = Fernet(key)
    return cipher.decrypt(encrypted_key).decode()

# Initializes the database. If the database file already exists, this function does nothing.
def create_database(master_password):
    if os.path.exists(DATABASE_FILENAME):
        return

    # Uses Argon2 to hash the master password securely.
    ph = PasswordHasher()
    master_hash = ph.hash(master_password)

    # Connects to the SQLite database and creates necessary tables.
    conn = sqlite3.connect(DATABASE_FILENAME)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS private_keys (
            image_path TEXT,
            salt BLOB,
            encrypted_key BLOB,
            creation_timestamp TEXT 
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS master_password (
            password_hash TEXT
        )
    ''')
    cursor.execute("INSERT INTO master_password VALUES (?)", (master_hash,))

    conn.commit()
    conn.close()

# Checks if the provided master password matches the hash stored in the database.
def check_master_password(master_password):
    ph = PasswordHasher()
    conn = sqlite3.connect(DATABASE_FILENAME)
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM master_password")
    result = cursor.fetchone()
    conn.close()

    if result:
        stored_hash = result[0]
        try:
            ph.verify(stored_hash, master_password)
            return True
        except:
            return False
    else:
        return False  # Indicates the database has not yet been initialized.

# Stores an encrypted private key in the database, associated with an image path.
def store_private_key(db_filename, private_key, master_password, image_path):
    if not key_database.check_master_password(master_password):
        print("Incorrect master password.")
        return False

    salt = generate_key_derivation_salt()
    encrypted_key = encrypt_private_key(private_key, master_password, salt)
    normalized_path = normalize_path(image_path)

    # Opens a connection to the database and inserts the encrypted key along with other metadata.
    conn = sqlite3.connect(db_filename)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO private_keys (image_path, salt, encrypted_key, creation_timestamp) VALUES (?, ?, ?, ?)",
                       (normalized_path, salt, encrypted_key, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        print("Key insertion confirmed.")
    except sqlite3.Error as e:
        print(f"Failed to insert key due to database error: {e}")
        return False
    finally:
        conn.close()
    return True

# Retrieves and decrypts a private key associated with a given image path, if available.
def load_private_key(image_path, master_password):
    normalized_path = normalize_path(image_path)
    if not check_master_password(master_password):
        print("Incorrect master password provided.")
        return None

    conn = sqlite3.connect(DATABASE_FILENAME)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT salt, encrypted_key FROM private_keys WHERE image_path=? ORDER BY creation_timestamp DESC LIMIT 1", (normalized_path,))
        result = cursor.fetchone()
        if result:
            salt, encrypted_key = result
            try:
                return decrypt_private_key(encrypted_key, master_password, salt)
            except Exception as e:
                print(f"Decryption failed: {e}")
                return None
        else:
            print(f"No private key found for the provided image path: {normalized_path}")
            return None
    finally:
        conn.close()
