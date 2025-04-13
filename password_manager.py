import os
import secrets
import sqlite3
import base64
import hashlib
import string
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from argon2.low_level import hash_secret_raw, Type
from generator import generate_password

# Argon constants
ARGON2_VERSION_13 = 0x13
ARGON2_TYPE_I  = 1
ARGON2_TYPE_ID = 2


# file paths for stored salt, hashed authentication key, and DB
SALT_FILE = "salt.bin"
AUTH_FILE = "auth_key.bin"
DB_FILE = "vault.db"

def argon2_hash_raw(password_ba, salt_ba,
                    t_cost=2,
                    m_cost=102400,
                    parallelism=8,
                    hash_len=32,
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

    # Clear sensitive data
    for i in range(len(password_ba)):
        password_ba[i] = 0

    return bytearray(hash_bytes)

# create password manager class
class PasswordManager:
    def __init__(self, db_file=DB_FILE, salt_file=SALT_FILE, auth_file=AUTH_FILE):
        self.db_file = db_file
        self.salt_file = salt_file
        self.auth_file = auth_file
        self.encryption_key = None

    def connect_database(self):
        conn = None
        try:
            conn = sqlite3.connect(self.db_file)
            print(f"Connected to db file: {self.db_file}")
        except sqlite3.Error as e:
            print(f"Error: {e}")
        return conn
    
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
            print("Table 'vault' created or already exists.")
        except sqlite3.Error as e:
            print(f"Error creating table: {e}")
    
    def initialize_database(self):
        
        # Connect to the database or create one
        conn = self.connect_database()
        
        # Drop if table exists already
        cursor = conn.cursor()
        cursor.execute("DROP TABLE IF EXISTS vault")
        conn.commit()
        
        # Create the table for storing entries if it doesn't exist
        self.create_pword_table(conn)
        
        return conn
    
    def display_database(self, conn):
        # access passwords
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM vault;")
            rows = cursor.fetchall()
        
            if rows:
                for row in rows:
                    try:
                        decrypted_password = self.decrypt_data(row[3], self.encryption_key)
                        print(f"ID: {row[0]}, Platform: {row[1]}, Username: {row[2]}, Password: {decrypted_password}")
                    except Exception as e:
                        print(f"Could not decrypt password for entry ID {row[0]}: {e}")
            else:
                print("No records found in the vault table.")
        except sqlite3.Error as e:
            print(f"Error reading from database: {e}")
            
        return
    
    def encrypt_entry(data, key):
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
        return base64.b64encode(iv + encryptor.tag + ciphertext).decode()
    
    def decrypt_data(self, encrypted_data: str, key: bytes):
        encrypted_data = base64.b64decode(encrypted_data.encode())
        iv, tag, ciphertext = encrypted_data[:12], encrypted_data[12:28], encrypted_data[28:]
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode()
    
    def add_entry(self, conn):
        # Add a password entry
        platform = input("Enter Platform: ")
        username = input("Enter username or email associated with platform: ")
        x = input("Input 1 to use your own password or 2 to have a strong password generated: ")
        
        if x == "1":
            user_input = input("Input password of length 16: ")
            password = bytearray(user_input, 'utf-8')
        elif x == "2":
            password = generate_password(16)
            print(password)
        else:
            print("Invalid input")
            return
          
        encrypted_password = PasswordManager.encrypt_entry(password.decode('utf-8'), self.encryption_key)
        
        for i in range(len(password)):
            password[i] = 0
          
        try:
            cursor = conn.cursor()
            cursor.execute("""
                           INSERT INTO vault (platform, username, password)
                           VALUES (?, ?, ?)
                           """, (platform, username, encrypted_password))
            conn.commit()
            print("Entry added")
        except sqlite3.Error as e:
            print(f"Error trying to add entry: {e}") 
        
        return
    
    def user_options(self, conn):
        # Creat loop that breaks when user is done with database
        while True:
            # prompt user to ask them what action they would like to carry out
            print("Please choose an action:")
            print("1.) Access Passwords")
            print("2.) Create new password entry")
            print("3.) Update password entry")
            print("4.) Delete passwprd entry")
            print("5.) Exit and close ")
            x = input("Enter choice: ")
            
            if x == "1":
                self.display_database(conn)
            elif x == "2":
                self.add_entry(conn)
            elif x == "3":
                self.update_entry(conn)
            elif x == "4":
                self.delete_entry(conn)
            elif x == "5":
                if self.encryption_key:
                    for i in range(len(self.encryption_key)):
                        self.encryption_key[i] = 0
                    self.encryption_key = None
                    print("Encryption key cleared from memory.")
                break
            else:
                print("Invalid Input")
                  
    # account creation
    def create_account(self, master_password_str: str):
        # Convert input to bytearray
        master_password = bytearray(master_password_str, 'utf-8')

        # Create salt then store in "salt.bin" for later authentication
        salt = os.urandom(16)
        with open(self.salt_file, "wb") as file:
            file.write(salt)

        # Derive a key from the master password using Argon2
        hash_val = argon2_hash_raw(
            password_ba=master_password,
            salt_ba=salt,
            t_cost=2,
            m_cost=102400,
            parallelism=8,
            hash_len=32,
            argon2_type=Type.I
        )

        # Split derived key into auth and encryption keys
        mid_hash = len(hash_val) // 2
        auth_key = hash_val[:mid_hash]
        encr_key = hash_val[mid_hash:]
        self.encryption_key = encr_key

        # Hash the authentication key using SHA-256
        hashed_auth_key = hashlib.sha256(auth_key).digest()

        # Clear auth key from memory
        for i in range(len(auth_key)):
            auth_key[i] = 0

        # Store hashed auth key in "auth_key.bin"
        with open(self.auth_file, "wb") as file:
            file.write(hashed_auth_key)

        # Clear master password and derived hash from memory
        for i in range(len(master_password)):
            master_password[i] = 0
        for i in range(len(hash_val)):
            hash_val[i] = 0

        # Initialize database
        conn = self.initialize_database()
        return conn

    # Function to access exisitng acoounts
    def access_account(self):
        # Ensure that the salt and hashed_auth_key files exist
        if not os.path.exists(self.salt_file) or not os.path.exists(self.auth_file):
            print("No existing account found. Please create an account first.")
            return

        # Load stored salt and hashed authentication key.
        with open(self.salt_file, "rb") as file:
            salt = file.read()

        with open(self.auth_file, "rb") as file:
            stored_hashed_auth = file.read()

        # Get master password
        user_input = input("Enter your master password:")
        master_password = bytearray(user_input, "utf-8")

        # Derive key from the provided master password using Argon2
        try:
            hash_val = argon2_hash_raw(
                password_ba=master_password,
                salt_ba=salt,
                t_cost=2,
                m_cost=102400,
                parallelism=8,
                hash_len=32,
                argon2_type=Type.I
            )
        except Exception as e:
            print(f"Key derivation failed: {e}")
            return
      
        # Hash the authentication key
        mid_hash = len(hash_val) // 2
        auth_key = hash_val[:mid_hash]
        encr_key = hash_val[mid_hash:]

        computed_auth_hash = hashlib.sha256(auth_key).digest()

        # Compare the computed authentication hash to the stored one. Authentication fails or is successful
        if computed_auth_hash != stored_hashed_auth:
            print("Authentication failed. Incorrect master password.")
            return

        # If authentication is successful save the encryption key.
        print("Authentication successful.")
        
        self.encryption_key = encr_key

        for i in range(len(master_password)):
            master_password[i] = 0
        for i in range(len(hash_val)):
            hash_val[i] = 0
        # Open the encrypted database.
        
        conn = self.connect_database()
        #self.create_pword_table(conn)  # Make sure table exists

        self.user_options(conn)
    
    # Function to update an exisitng entry
    def update_entry(self, conn):
        cursor = conn.cursor()

        # Step 1: Ask for the platform name
        platform = input("Enter the platform name of the entry you want to update: ")

        cursor.execute("SELECT id, username FROM vault WHERE platform = ?", (platform,))
        rows = cursor.fetchall()

        if not rows:
            print("No entries found for that platform.")
            return

        # Step 2: Display matching entries
        print(f"\nEntries for platform '{platform}':")
        for row in rows:
            print(f"ID: {row[0]}, Username: {row[1]}")

        # If multiple entries, ask which ID to update
        try:
            entry_id = int(input("\nEnter the ID of the entry you want to update: "))
        except ValueError:
            print("Invalid ID.")
            return

        # Step 3: Choose fields to update
        print("What would you like to update?")
        print("1. Username")
        print("2. Password")
        print("3. Both")
        choice = input("Enter choice: ")

        if choice not in ["1", "2", "3"]:
            print("Invalid choice.")
            return

        new_username = None
        new_password = None

        if choice in ["1", "3"]:
            new_username = input("Enter new username: ")

        if choice in ["2", "3"]:
            x = input("Input 1 to enter your own password or 2 to generate a strong one: ")
            if x == "1":
                user_input = input("Enter new password of length 16: ")
                password_ba = bytearray(user_input, 'utf-8')
            elif x == "2":
                password_ba = generate_password(16)
            else:
                print("Invalid input.")
                return

            # Encrypt password
            new_password = PasswordManager.encrypt_entry(password_ba.decode('utf-8'), self.encryption_key)

            # Clear sensitive data
            for i in range(len(password_ba)):
                password_ba[i] = 0

        # Step 4: Run the update query
        try:
            if new_username and new_password:
                cursor.execute("""
                    UPDATE vault SET username = ?, password = ? WHERE id = ?
                """, (new_username, new_password, entry_id))
            elif new_username:
                cursor.execute("""
                    UPDATE vault SET username = ? WHERE id = ?
                """, (new_username, entry_id))
            elif new_password:
                cursor.execute("""
                    UPDATE vault SET password = ? WHERE id = ?
                """, (new_password, entry_id))
            else:
                print("Nothing to update.")
                return

            conn.commit()
            print("Entry updated successfully.")
        except sqlite3.Error as e:
            print(f"Error updating entry: {e}")
        
    # Function to delete an entry
    def delete_entry(self, conn):
        cursor = conn.cursor()

        # Step 1: Ask for the platform
        platform = input("Enter the platform of the entry you want to delete: ")

        cursor.execute("SELECT id, username FROM vault WHERE platform = ?", (platform,))
        rows = cursor.fetchall()

        if not rows:
            print("No entries found for that platform.")
            return

        # Step 2: Show matching entries
        print(f"\nEntries for platform '{platform}':")
        for row in rows:
            print(f"ID: {row[0]}, Username: {row[1]}")

        # Step 3: User selects ID to delete
        try:
            entry_id = int(input("\nEnter the ID of the entry you want to delete: "))
        except ValueError:
            print("Invalid ID.")
            return

        # Step 4: Confirm and delete
        confirm = input("Are you sure you want to delete this entry? (y/n): ").lower()
        if confirm != "y":
            print("Deletion canceled.")
            return

        try:
            cursor.execute("DELETE FROM vault WHERE id = ?", (entry_id,))
            conn.commit()
            print("Entry deleted successfully.")
        except sqlite3.Error as e:
            print(f"Error deleting entry: {e}")


    