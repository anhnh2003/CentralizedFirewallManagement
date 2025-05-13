import hashlib
import secrets

def hash_password(password: str) -> str:
    """Tạo password hash với salt ngẫu nhiên (định dạng: salt:hash)"""
    salt = secrets.token_hex(16)  # Tạo salt 16 bytes (32 ký tự hex)
    hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000  # Số lần lặp
    ).hex()
    return f"{salt}:{hash}"

def verify_password(password: str, hashed: str) -> bool:
    """Xác thực mật khẩu"""
    try:
        salt, original_hash = hashed.split(':')
        new_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000
        ).hex()
        return secrets.compare_digest(new_hash, original_hash)
    except:
        return False
