import os
import secrets
import sqlite3
import hashlib
import string
from argon2.low_level import hash_secret_raw

# Argon and salt constants

# temp file paths for stored salt and hashed authentication key
SALT_FILE = "salt.bin"
AUTH_FILE = "auth_key.bin"
DB_FILE = "vault.db"

# create password manager class
class PasswordManager:
    def __init__(self, db_file=DB_FILE, salt_file=SALT_FILE, auth_file=AUTH_FILE):
        self.db_file = db_file
        self.salt_file = salt_file
        self.auth_file = auth_file

    # account creation
    def create_account():
        
        # Generate a secure random salt
        salt

        # Derive a key from the master password using Argon2
        # The derived key is ARGON2_HASH_LEN bytes long
        key 

        # Split the key into two halves. Authentication and Encryption of DB
       
       
        # Hash the authentication key using SHA-256.
        auth_key_hash

        # Store the salt and the hashed authentication key in files.
        
        # Clear the master password from memory
        
        
        # Save the encryption key for the session.
        self.encryption_key = encryption_key

        # Initialize the encrypted SQLite database.
        self._initialize_database(encryption_key)

    # Function to intialize the password vault
    def _initialize_database():
        
        # Connect to the database or create one

        # Create the table for storing entries if it doesn't exist
        

    # Function to access exisitng acoounts
    def access_account():
        # Ensure that the salt and hashed_auth_key files exist


        # Load stored salt and hashed authentication key.


        # Derive key from the provided master password using Argon2
      
      
        # Hash the authentication key
        

        # Compare the computed authentication hash to the stored one. Authentication fails or is successful
        

        # If authentication is successful save the encryption key.
        

        # Open the encrypted database.
        
        
        # Test to ensure proper decryption of vault 
    

    # Function to add an entry to the vault
    def add_entry():
        
    # Function to retrieve all entries from the vault
    def get_entries(self):

    # Function to update an exisitng entry
    def update_entry():
        
    # Function to delete an entry
    def delete_entry():

    # logoff from database and clear memory
    def logout(self):
    