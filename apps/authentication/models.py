# -*- encoding: utf-8 -*-
from flask_login import UserMixin
from apps import db, login_manager
from apps.authentication.util import hash_pass  # Giả sử bạn có hàm hash_pass trong 'utils'

class Users(db.Model, UserMixin):
    __tablename__ = 'users'  # Đảm bảo bảng tên là 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)  # Tương ứng với trường 'username'
    password_hash = db.Column(db.String(256), nullable=False)  # Tương ứng với 'password_hash'
    role = db.Column(db.Enum('user', 'admin', name='role_enum'), nullable=False)  # ENUM('user', 'admin')
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())  # Tương ứng với 'created_at'
    updated_at = db.Column(db.DateTime)  # Tương ứng với 'updated_at'

    def __init__(self, **kwargs):
        for property, value in kwargs.items():
            # Nếu có giá trị iterable, unpack giá trị đó
            if hasattr(value, '__iter__') and not isinstance(value, str):
                value = value[0]
            if property == 'password':
                value = hash_pass(value)  # Giả sử bạn có hàm hash_pass trong 'utils' để băm mật khẩu
            setattr(self, property, value)
    def get_id(self):  # Quan trọng cho Flask-Login
        return str(self.id)
    def __repr__(self):
        return f'<User {self.username}>'

# Hàm load người dùng từ session
@login_manager.user_loader
def user_loader(id):
    return Users.query.get(int(id))

@login_manager.request_loader
def request_loader(request):
    username = request.form.get('username')
    user = Users.query.filter_by(username=username).first()
    return user if user else None
