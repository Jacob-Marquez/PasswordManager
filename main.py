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
    
    pm.access_account()
    