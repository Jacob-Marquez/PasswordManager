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
                    print(row)
            else:
                print("No records found in the vault table.")
        except sqlite3.Error as e:
            print(f"Error reading from database: {e}")
            
        return
    
    def add_entry(self, conn):
        # Add a password entry
        platform = input("Enter Platform: ")
        username = input("Enter username or email associated with platform: ")
        x = input("Input 1 to use your own password or 2 to have a strong password generated: ")
        
        if x == "1":
            print("Input password of length 16:")
            str = input()
            master_password = bytearray(str, 'utf-8')
        elif x == "2":
            master_password = generate_password(10)
        else:
            print("Invalid input")
        
        return
    
    def close_vault(self, conn):
        # Close connection with database and encrypt again
        return
    
    def user_options(self, conn):
        # Creat loop that breaks when user is done with database
        while True:
            # prompt user to ask them what action they would like to carry out
            print("Please choose an action:")
            print("1.) Access Passwords")
            print("2.) Create new password entry")
            print("3.) Exit and close")
            x = input("Enter choice: ")
            
            if x == "1":
                self.display_database(conn)
            elif x == "2":
                self.add_entry(conn)
            elif x == "3":
                self.close_vault(conn)
                break
            else:
                print("Invalid Input")
                
    
    # account creation
    def create_account(self):
        
        print("Welcome User. Press 1 to enter a master password. Press 2 if you would like to have password generated.")
        x = input()
        
        # Master Password creation
        if x == "1":
            print("Input Master Password of length 16:")
            str = input()
            master_password = bytearray(str, 'utf-8')
        elif x == "2":
            master_password = generate_password(16)
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
        
        conn = self.initialize_database()
        # Initialize the encrypted SQLite database. initialize_database(encr_key)
        
        self.user_options(conn)
    
    
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