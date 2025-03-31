import os
import secrets
import sqlite3
import hashlib
import string
import getpass
from argon2.low_level import hash_secret_raw, Type
from password_manager import PasswordManager
from generator import generate_password


# File paths for stored salt and hashed authentication key
SALT_FILE = "salt.bin"
AUTH_FILE = "auth_key.bin"
DB_FILE = "vault.db"


if __name__ == "__main__":
    pm = PasswordManager()
    pm.create_account()
    
    """
    password = generate_password()
    print(password)
    
    salt = os.urandom(16)
    with open("salt.bin", "wb") as file:
        file.write(salt)
    print(salt)
    
    hash_val = hash_secret_raw(
    password.encode("utf-8"),
    salt,
    time_cost=2,
    memory_cost=102400,
    parallelism=8,
    hash_len=32,
    type=Type.I
    )

    print("Hash (hex):", hash_val.hex())
    print(hash_val)
    
    
    with open("salt.bin", "rb") as file:
        newsalt = file.read()
    
    new_hash_val = hash_secret_raw(
    password.encode("utf-8"),
    newsalt,
    time_cost=2,
    memory_cost=102400,
    parallelism=8,
    hash_len=32,
    type=Type.I
    )
    
    print("Hash (hex):", new_hash_val.hex())
    
    
    mid_hash = len(hash_val)//2
    
    auth_key = hash_val[:mid_hash]
    encr_key = hash_val[mid_hash:]
    
    print("Auth: ",auth_key.hex())
    print("Encr: ",encr_key.hex())
    
    hashed_auth_key = hashlib.sha256(auth_key).digest()
    print(hashed_auth_key.hex())
    
    with open("auth_key.bin", "wb") as file:
        file.write(hashed_auth_key)
    
    
    conn = create_vault_connection(DB_FILE)
    
    if conn is not None:
        create_table(conn)
        
        try:
            cursor = conn.cursor()
            cursor.execute("""
"""
               INSERT INTO vault (platform, username, password)
                VALUES (?, ?, ?);
                """
""", ("TestPlatform", "TestUser", "TestPassword123"))
            
            conn.commit()
            print("Successfully inserted a test record.")
            print_all_records(conn)
        except sqlite3.Error as e:
            print(f"Error inserting record: {e}")
        
        conn.close()
        print("closed")
    else:
        print("Error connecting")
    """