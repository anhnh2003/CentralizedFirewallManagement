import hashlib
import binascii
import os

def hash_pass(password):
    salt = os.urandom(64)
    pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), salt, 100000)
    pwdhash = binascii.hexlify(pwdhash).decode('ascii')
    return salt.hex() + pwdhash

# Mã hóa mật khẩu '1'
hashed_password = hash_pass('1')
print(hashed_password)
print(len(hashed_password))