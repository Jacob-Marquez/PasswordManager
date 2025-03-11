import secrets
import string


def generate_password(length, allowed_chars=string.ascii_letters + string.digits + string.punctuation) -> bytearray:
    
    allowed_bytes = allowed_chars.encode("ascii", errors="replace")
    
    password = bytearray(length)
    
    for i in range(length):
        x = secrets.randbelow(len(allowed_bytes))
        password[i] = allowed_bytes[x]
        
    return password

