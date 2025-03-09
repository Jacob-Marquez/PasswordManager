import os
import secrets
import sqlite3
import hashlib
import string
import cffi
from argon2.low_level import hash_secret_raw, Type
from generator import generate_password

ffi = cffi.FFI()
ffi.cdef("""
int argon2_hash(
    unsigned int t_cost,
    unsigned int m_cost,
    unsigned int parallelism,
    const void *pwd, size_t pwdlen,
    const void *salt, size_t saltlen,
    void *hash, size_t hashlen,
    char *encoded, size_t encodedlen,
    int argon2_type,
    unsigned int version
);

const char *argon2_error_message(int error_code);
""")

argon2 = ffi.dlopen("C:/Users/jacob/vcpkg/installed/x64-windows/bin/argon2.dll")

# Argon constants
ARGON2_VERSION_13 = 0x13
ARGON2_TYPE_I  = 1
ARGON2_TYPE_ID = 2

def argon2_hash_raw(password_ba, salt_ba,
                    t_cost=2,
                    m_cost=102400,
                    parallelism=8,
                    hash_len=32,
                    argon2_type=ARGON2_TYPE_I):
    pwd_len = len(password_ba)
    salt_len = len(salt_ba)
    pwd_buf  = ffi.new("unsigned char[]", pwd_len)
    salt_buf = ffi.new("unsigned char[]", salt_len)
    out_buf  = ffi.new("unsigned char[]", hash_len)

    ffi.memmove(pwd_buf, bytes(password_ba), pwd_len)
    ffi.memmove(salt_buf, bytes(salt_ba), salt_len)

    encoded_ptr = ffi.NULL
    encoded_len = 0

    rc = argon2.argon2_hash(
        t_cost,
        m_cost,
        parallelism,
        pwd_buf, pwd_len,
        salt_buf, salt_len,
        out_buf, hash_len,
        encoded_ptr, encoded_len,
        argon2_type,
        ARGON2_VERSION_13
    )

    if rc != 0:
        err_msg_ptr = argon2.argon2_error_message(rc)
        err_msg = ffi.string(err_msg_ptr).decode("utf-8", "replace")
        for i in range(pwd_len):
            pwd_buf[i] = 0
        raise RuntimeError(f"argon2_hash failed with code {rc}: {err_msg}")

    for i in range(pwd_len):
        pwd_buf[i] = 0

    return out_buf

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
        
        print("Welcome User. Press 1 to enter a master password. Press 2 if you would like to have password generated.")
        x = input()
        
        # Master Password creation
        if x == "1":
            print("Input Master Password of length 16:")
            str = input()
            master_password = bytearray(str, 'utf-8')
        elif x == "2":
            master_password = generate_password()
        else:
            print("Invalid input")
            
        print(master_password)
        
        # Create salt then store in "salt.bin" for later authentication
        salt = os.urandom(16)
        with open("salt.bin", "wb") as file:
            file.write(salt)
        print(salt)
            
        # Derive a key from the master password using Argon2
        # The derived key is ARGON2_HASH_LEN bytes long
        ptr_val = argon2_hash_raw(
            password_ba=master_password,
            salt_ba=salt,
            t_cost=2,
            m_cost=102400,
            parallelism=8,
            hash_len=32,
            argon2_type=ARGON2_TYPE_I
        )

        hash_val = bytearray(ptr_val)
        print(hash_val)
            
        # Split the key into two halves. Authentication key and Encryption key for DB
        mid_hash = len(hash_val)//2
    
        auth_key = hash_val[:mid_hash]
        encr_key = hash_val[mid_hash:]
    
        print("Auth: ",auth_key.hex())
        print("Encr: ",encr_key.hex())
       
        # Hash the authentication key using SHA-256.
        hashed_auth_key = hashlib.sha256(auth_key).digest()
        print(hashed_auth_key.hex())
        
        # Store hashed auth key in "auth_key.bin"
        with open("auth_key.bin", "wb") as file:
            file.write(hashed_auth_key)
            
        # Clear all data necessary from data
        ffi.memmove(ptr_val, b"\x00" * 32, 32)
        
        for i in range(len(master_password)):
            master_password[i] = 0
        
        print("Huzzah!")
        # Initialize database
        
        conn = initialize_database()
        # Initialize the encrypted SQLite database. initialize_database(encr_key)
        
    
    # Function to intialize the password vault
    def initialize_database():
        
        # Connect to the database or create one
        conn = connect_database(DB_FILE)
        # Create the table for storing entries if it doesn't exist
        create_pword_table(conn)
        
        return conn
    
    
    def connect_database(db_name):
        conn = None
        try:
            conn = sqlite3.connect(db_name)
            print(f"Connected to db file: {db_name}")
        except sqlite3.Error as e:
            print(f"Error: {e}")
        return conn
    
    def create_pword_table(conn):
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
        
        
        """
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
    """