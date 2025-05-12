# -*- encoding: utf-8 -*- 
""" Copyright (c) 2019 - present AppSeed.us """

import os

class Config(object):
    basedir = os.path.abspath(os.path.dirname(__file__))
    
    # Secret key configuration
    SECRET_KEY = os.getenv('SECRET_KEY', 'S#perS3crEt_007')
    
    # Database configuration (MySQL)
    SQLALCHEMY_DATABASE_URI = 'mysql://admin:1@localhost/iptables_management'  # Thay 'admin' và '1' với credentials
    SQLALCHEMY_TRACK_MODIFICATIONS = False  # Tắt tính năng theo dõi thay đổi của SQLAlchemy (giảm tải)
    
    # Assets management
    ASSETS_ROOT = os.getenv('ASSETS_ROOT', '/static/assets')

class ProductionConfig(Config):
    DEBUG = False  # Chạy ở chế độ sản xuất
    SESSION_COOKIE_HTTPONLY = True  # Bảo mật cookie
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_DURATION = 3600  # Thời gian giữ phiên làm việc

class DebugConfig(Config):
    DEBUG = True  # Chạy ở chế độ debug

# Load các cấu hình tùy thuộc vào môi trường
config_dict = {
    'Production': ProductionConfig,
    'Debug': DebugConfig
}
