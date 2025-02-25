import secrets
import string


def generate_password(length=16, allowed_chars=string.ascii_letters + string.digits + string.punctuation):
    return ''.join(secrets.choice(allowed_chars) for _ in range(length))

