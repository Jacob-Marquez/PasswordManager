import os
import secrets
import sqlite3
import hashlib
import string
from argon2.low_level import hash_secret_raw

# Argon and salt constants

# temp file paths for stored salt and hashed authentication key
SALT_FILE = "salt.bin"
AUTH_FILE = "auth_key.hash"
DB_FILE = "vault.db"

# create password manager class
class PasswordManager:
    def __init__(self, db_file=DB_FILE, salt_file=SALT_FILE, auth_file=AUTH_FILE):
        self.db_file = db_file
        self.salt_file = salt_file
        self.auth_file = auth_file

    # account creation
    def create_account(self, master_password: str):
        """
        Create a new account:
          - Generates a random salt.
          - Derives a key from the master password using Argon2.
          - Splits the derived key into an authentication key and an encryption key.
          - Hashes the authentication key with SHA-256 and stores it with the salt.
          - Initializes an encrypted SQLite database.
        """
        # Generate a secure random salt
        salt

        # Derive a key from the master password using Argon2
        # The derived key is ARGON2_HASH_LEN bytes long
        key 

        # Split the key into two halves. Authentication and Encryption of DB
        half = ARGON2_HASH_LEN // 2
        auth_key = key[:half]
        encryption_key = key[half:]

        # Hash the authentication key using SHA-256.
        auth_key_hash

        # Store the salt and the hashed authentication key in files.
        with open(self.salt_file, 'wb') as f:
            f.write(salt)
        with open(self.auth_file, 'wb') as f:
            f.write(auth_key_hash)

        # Clear the master password from memory
        
        
        # Save the encryption key for the session.
        self.encryption_key = encryption_key

        # Initialize the encrypted SQLite database.
        self._initialize_database(encryption_key)

    # Function to intialize the 
    def _initialize_database(self, encryption_key: bytes):
        """
        Create and initialize the encrypted SQLite database (password vault).
        This uses SQLCipher via SQLite PRAGMA commands.
        """
        # Connect to the database (creates the file if it doesn't exist).
        self.conn = sqlite3.connect(self.db_file)
        cursor = self.conn.cursor()

        # SQLCipher requires setting a key via PRAGMA.
        # Here we convert the binary key to a hex string.
        key_hex = encryption_key.hex()
        cursor.execute(f"PRAGMA key = \"x'{key_hex}'\";")

        # Create the table for storing entries if it doesn't exist.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                platform TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            );
        """)
        self.conn.commit()

    def access_account(self, master_password: str) -> bool:
        """
        Attempt to access an existing account:
          - Loads the stored salt and hashed authentication key.
          - Derives keys from the provided master password.
          - Compares the derived authentication key hash with the stored hash.
          - If verified, opens and decrypts the SQLite database.
        Returns True if access is granted; otherwise, False.
        """
        # Ensure that the required files exist.
        if not os.path.exists(self.salt_file) or not os.path.exists(self.auth_file):
            print("Account does not exist. Please create an account first.")
            return False

        # Load stored salt and hashed authentication key.
        with open(self.salt_file, 'rb') as f:
            salt = f.read()
        with open(self.auth_file, 'rb') as f:
            stored_auth_hash = f.read()

        # Derive key from the provided master password using Argon2.
        key = hash_secret_raw(
            password=master_password.encode('utf-8'),
            salt=salt,
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST,
            parallelism=ARGON2_PARALLELISM,
            hash_len=ARGON2_HASH_LEN,
            type=ARGON2_TYPE
        )
        half = ARGON2_HASH_LEN // 2
        auth_key = key[:half]
        encryption_key = key[half:]

        # Hash the authentication key.
        auth_key_hash = hashlib.sha256(auth_key).digest()

        # Compare the computed authentication hash to the stored one.
        if auth_key_hash != stored_auth_hash:
            print("Authentication failed: Incorrect master password.")
            return False

        # Authentication successful; save the encryption key.
        self.encryption_key = encryption_key

        # Open the encrypted database.
        self.conn = sqlite3.connect(self.db_file)
        key_hex = encryption_key.hex()
        cursor = self.conn.cursor()
        cursor.execute(f"PRAGMA key = \"x'{key_hex}'\";")
        try:
            # Test the decryption by querying the schema.
            cursor.execute("SELECT count(*) FROM sqlite_master;")
            cursor.fetchall()
        except sqlite3.DatabaseError:
            print("Failed to decrypt database. Possibly wrong encryption key.")
            return False

        print("Access granted. Database unlocked.")
        return True

    def add_entry(self, platform: str, username: str, password: str):
        """
        Add a new credential entry to the vault.
        """
        if self.conn is None:
            print("No active database connection. Please log in.")
            return
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO entries (platform, username, password) VALUES (?, ?, ?)",
            (platform, username, password)
        )
        self.conn.commit()
        print("Entry added successfully.")

    def get_entries(self):
        """
        Retrieve all entries from the vault.
        """
        if self.conn is None:
            print("No active database connection. Please log in.")
            return []
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, platform, username, password FROM entries")
        return cursor.fetchall()

    def update_entry(self, entry_id: int, platform: str = None, username: str = None, password: str = None):
        """
        Update an existing entry. Only non-None fields will be updated.
        """
        if self.conn is None:
            print("No active database connection. Please log in.")
            return
        cursor = self.conn.cursor()

        # Dynamically build the update statement.
        fields = []
        params = []
        if platform:
            fields.append("platform = ?")
            params.append(platform)
        if username:
            fields.append("username = ?")
            params.append(username)
        if password:
            fields.append("password = ?")
            params.append(password)
        if not fields:
            print("No fields provided to update.")
            return

        params.append(entry_id)
        query = "UPDATE entries SET " + ", ".join(fields) + " WHERE id = ?"
        cursor.execute(query, tuple(params))
        self.conn.commit()
        print("Entry updated successfully.")

    def delete_entry(self, entry_id: int):
        """
        Delete an entry from the vault by its ID.
        """
        if self.conn is None:
            print("No active database connection. Please log in.")
            return
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
        self.conn.commit()
        print("Entry deleted successfully.")

    def generate_password(self, length: int = 16, 
                          allowed_chars: str = string.ascii_letters + string.digits + string.punctuation) -> str:
        """
        Generate a secure random password.
        Uses the secrets module to pick characters uniformly at random.
        """
        return ''.join(secrets.choice(allowed_chars) for _ in range(length))

    def logout(self):
        """
        Log out of the account:
          - Close the database connection.
          - Clear the encryption key from memory.
        """
        if self.conn:
            self.conn.close()
        self.conn = None
        self.encryption_key = None
        print("Logged out and keys cleared.")