import os
import secrets
import sqlite3
import hashlib
import string
from argon2.low_level import hash_secret_raw
from password_manager import PasswordManager

# -----------------------
# Configuration Constants
# -----------------------

SALT_SIZE = 16  # 16 bytes salt
ARGON2_TIME_COST = 2
ARGON2_MEMORY_COST = 102400  # Memory cost in kibibytes (e.g. ~100MB)
ARGON2_PARALLELISM = 8
ARGON2_HASH_LEN = 64  # Total length (in bytes) of the derived key
ARGON2_TYPE = Type.I  # Using Argon2i; you might also consider Argon2id

# File paths for stored salt and hashed authentication key
SALT_FILE = "salt.bin"
AUTH_FILE = "auth_key.hash"
DB_FILE = "vault.db"


# -----------------------
# Example Usage (CLI)
# -----------------------

if __name__ == "__main__":
    import getpass

    pm = PasswordManager()
    print("Welcome to the Password Manager.")

    action = input("Do you want to (1) create an account or (2) access an account? Enter 1 or 2: ").strip()
    
    if action == "1":
        master_password = getpass.getpass("Create a master password: ")
        pm.create_account(master_password)
    
    elif action == "2":
        master_password = getpass.getpass("Enter your master password: ")
        if pm.access_account(master_password):
            # Simple CLI menu after successful login
            while True:
                print("\nMenu:")
                print("1. Add new entry")
                print("2. List entries")
                print("3. Update an entry")
                print("4. Delete an entry")
                print("5. Generate a secure password")
                print("6. Logout")
                choice = input("Choose an option: ").strip()

                if choice == "1":
                    platform = input("Enter platform: ")
                    username = input("Enter username: ")
                    gen_choice = input("Generate a secure password? (y/n): ").lower().strip()
                    if gen_choice == 'y':
                        password = pm.generate_password()
                        print("Generated password:", password)
                    else:
                        password = input("Enter password: ")
                    pm.add_entry(platform, username, password)

                elif choice == "2":
                    entries = pm.get_entries()
                    if entries:
                        for entry in entries:
                            print(f"ID: {entry[0]}, Platform: {entry[1]}, Username: {entry[2]}, Password: {entry[3]}")
                    else:
                        print("No entries found.")

                elif choice == "3":
                    try:
                        entry_id = int(input("Enter the entry ID to update: "))
                    except ValueError:
                        print("Invalid ID.")
                        continue
                    platform = input("Enter new platform (or press enter to skip): ")
                    username = input("Enter new username (or press enter to skip): ")
                    password = input("Enter new password (or press enter to skip): ")
                    pm.update_entry(
                        entry_id,
                        platform if platform else None,
                        username if username else None,
                        password if password else None
                    )

                elif choice == "4":
                    try:
                        entry_id = int(input("Enter the entry ID to delete: "))
                    except ValueError:
                        print("Invalid ID.")
                        continue
                    pm.delete_entry(entry_id)

                elif choice == "5":
                    try:
                        length = int(input("Enter desired password length: "))
                    except ValueError:
                        print("Invalid length.")
                        continue
                    generated = pm.generate_password(length)
                    print("Generated password:", generated)

                elif choice == "6":
                    pm.logout()
                    break

                else:
                    print("Invalid option.")
    
    else:
        print("Invalid option selected.")
