# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

import os
import hashlib
import binascii

# Inspiration -> https://www.vitoshacademy.com/hashing-passwords-in-python/


def hash_pass(password):
    """Hash a password for storing."""

    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'),
                                  salt, 100000)
    pwdhash = binascii.hexlify(pwdhash)
    return (salt + pwdhash)  # return bytes




def verify_pass(provided_password, stored_password):
    """Verify a stored password against one provided by user"""

    try:
        # Kiểm tra nếu stored_password là bytes (cần phải giải mã base64)
        if isinstance(stored_password, bytes):
            stored_password = stored_password.decode('ascii')

        # Giả sử mật khẩu đã lưu dưới dạng base64 (salt + password hash)
        # Nếu mật khẩu đã mã hóa bằng base64, giải mã nó
        if stored_password.startswith('base64:'):
            stored_password = base64.b64decode(stored_password[7:]).decode('ascii')

        # Tách salt và mật khẩu đã băm
        salt = stored_password[:64]
        stored_password_hash = stored_password[64:]

        # Băm mật khẩu người dùng nhập vào với cùng salt
        pwdhash = hashlib.pbkdf2_hmac('sha512',
                                      provided_password.encode('utf-8'),
                                      salt.encode('ascii'),
                                      100000)

        # Chuyển đổi băm sang hex để so sánh
        pwdhash = binascii.hexlify(pwdhash).decode('ascii')

        # Kiểm tra mật khẩu đã băm với mật khẩu lưu trữ
        return pwdhash == stored_password_hash
    except Exception as e:
        print(f"Error in password verification: {e}")
        return False
