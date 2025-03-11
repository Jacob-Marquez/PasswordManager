# Password Manager

## Overview

This project is intended to be a secure local password manager implemented with Python. It provides a local vault for storing user credentials and includes password generation and encryption features. The project looks to follow security best practices, including Argon2 and SHA 256 hashing, AES-256 encryption, and SQLite for database storage.

- **main.py**
  - Used to run
    
- **password_manager.py**
  - File contains all functions to create and access a user's account
    
- **generator.py**
  - File contains function to generate secure passwords. Uses a cryptographically secure random number generator for enhanced security.

## Features

- **Master Password Authentication**  
  - Users create a master password, which is hashed using Argon2 with a randomly generated salt.
  - The hashed password is split into an authentication key and an encryption key.
  - The authentication key is hashed with SHA-256 and stored securely.

- **Password Vault**  
  - User credentials (platform, username, password) are stored in an SQLite database.
  - Entries can be added, modified, or deleted.
  - Added entries will be encrypted using AES-256 and the derived encryption key
  - When trying to access entries they will be decrypted using the derived encryption key

- **Secure Password Generation**  
  - Users can choose to generate a strong password using the `secrets` module.


