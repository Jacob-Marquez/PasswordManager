import secrets
import string


def generate_password(length=16, 
                      allowed_chars=string.ascii_letters + string.digits + string.punctuation):
    """
    Generates a random password of a specified length using a CSPRNG.
    
    Parameters:
        length (int): Length of the password.
        allowed_chars (str): A string of characters from which to build the password.
    
    Returns:
        str: The generated password.
    """
    return ''.join(secrets.choice(allowed_chars) for _ in range(length))

# Example usage:
password = generate_password()
print("Generated password:", password)
