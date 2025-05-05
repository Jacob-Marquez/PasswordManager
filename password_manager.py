import os
import sqlite3
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from argon2.low_level import hash_secret_raw, Type
from generator import generate_password

# File paths for stored salt, hashed authentication key, and database file
SALT_FILE = "salt.bin"
AUTH_FILE = "auth_key.bin"
DB_FILE = "vault.db"

def argon2_hash_raw(password_ba, salt_ba,
                    t_cost=2,
                    m_cost=102400,
                    parallelism=8,
                    hash_len=64,
                    argon2_type=Type.I):
    
    password_bytes = bytes(password_ba)
    salt_bytes = bytes(salt_ba)
    
    hash_bytes = hash_secret_raw(
        secret=password_bytes,
        salt=salt_bytes,
        time_cost=t_cost,
        memory_cost=m_cost,
        parallelism=parallelism,
        hash_len=hash_len,
        type=argon2_type
    )

    # Clear sensitive data from the input bytearray.
    for i in range(len(password_ba)):
        password_ba[i] = 0

    return bytearray(hash_bytes)

class PasswordManager:
    def __init__(self, db_file=DB_FILE, salt_file=SALT_FILE, auth_file=AUTH_FILE):
        self.db_file = db_file
        self.salt_file = salt_file
        self.auth_file = auth_file
        self.encryption_key = None

    def connect_database(self):
        try:
            conn = sqlite3.connect(self.db_file)
            # Harden file permissions on the database file.
            if os.path.exists(self.db_file):
                os.chmod(self.db_file, 0o600)
            return conn
        except sqlite3.Error:
            raise Exception("An error occurred while connecting to the database.")

    def create_pword_table(self, conn):
        try:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vault (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    platform TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL
                );
            """)
            conn.commit()
        except sqlite3.Error:
            raise Exception("An error occurred while creating the table.")

    def initialize_database(self):
        conn = self.connect_database()
        if conn is not None:
            try:
                cursor = conn.cursor()
                # For account creation, drop the vault table for a fresh start.
                cursor.execute("DROP TABLE IF EXISTS vault")
                conn.commit()
                self.create_pword_table(conn)
            except Exception:
                raise Exception("An error occurred while initializing the database.")
        return conn

    @staticmethod
    def encrypt_entry(data, key):
        try:
            iv = os.urandom(12)
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
            return base64.b64encode(iv + encryptor.tag + ciphertext).decode()
        except Exception:
            raise Exception("An error occurred during encryption.")

    def decrypt_data(self, encrypted_data: str, key: bytes):
        try:
            encrypted_bytes = base64.b64decode(encrypted_data.encode())
            iv = encrypted_bytes[:12]
            tag = encrypted_bytes[12:28]
            ciphertext = encrypted_bytes[28:]
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            return (decryptor.update(ciphertext) + decryptor.finalize()).decode()
        except Exception:
            raise Exception("An error occurred during decryption.")

    def create_account(self, master_password_str: str):
        master_password = bytearray(master_password_str, 'utf-8')
        try:
            # Generate and store a new salt.
            salt = os.urandom(16)
            with open(self.salt_file, "wb") as file:
                file.write(salt)
            os.chmod(self.salt_file, 0o600)
        except Exception:
            raise Exception("An error occurred while writing the salt file.")

        # Derive key using Argon2.
        hash_val = argon2_hash_raw(
            password_ba=master_password,
            salt_ba=salt,
            t_cost=2,
            m_cost=102400,
            parallelism=8,
            hash_len=64,
            argon2_type=Type.I
        )
        mid_hash = len(hash_val) // 2
        auth_key = hash_val[:mid_hash]
        encr_key = hash_val[mid_hash:]
        self.encryption_key = encr_key
        try:
            hashed_auth_key = hashlib.sha256(auth_key).digest()
            with open(self.auth_file, "wb") as file:
                file.write(hashed_auth_key)
            os.chmod(self.auth_file, 0o600)
        except Exception:
            raise Exception("An error occurred while writing the authentication file.")
        # Clear sensitive data.
        for i in range(len(auth_key)):
            auth_key[i] = 0
        for i in range(len(master_password)):
            master_password[i] = 0
        for i in range(len(hash_val)):
            hash_val[i] = 0

        conn = self.initialize_database()
        return conn

    def access_account_gui(self, master_password: str):
        if not os.path.exists(self.salt_file) or not os.path.exists(self.auth_file):
            raise Exception("No existing account found. Please create an account first.")
        try:
            with open(self.salt_file, "rb") as file:
                salt = file.read()
            with open(self.auth_file, "rb") as file:
                stored_hashed_auth = file.read()
        except Exception:
            raise Exception("An error occurred while reading authentication files.")

        master_password_ba = bytearray(master_password, "utf-8")
        try:
            hash_val = argon2_hash_raw(
                password_ba=master_password_ba,
                salt_ba=salt,
                t_cost=2,
                m_cost=102400,
                parallelism=8,
                hash_len=64,
                argon2_type=Type.I
            )
        except Exception:
            raise Exception("Key derivation failed.")
        mid_hash = len(hash_val) // 2
        auth_key = hash_val[:mid_hash]
        encr_key = hash_val[mid_hash:]
        computed_auth_hash = hashlib.sha256(auth_key).digest()
        if computed_auth_hash != stored_hashed_auth:
            raise Exception("Authentication failed. Incorrect master password.")
        self.encryption_key = encr_key
        for i in range(len(master_password_ba)):
            master_password_ba[i] = 0
        for i in range(len(hash_val)):
            hash_val[i] = 0

        conn = self.connect_database()
        self.create_pword_table(conn)
        return conn
