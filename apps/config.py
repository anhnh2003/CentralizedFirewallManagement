import os

class Config(object):
    # Đường dẫn của ứng dụng
    basedir = os.path.abspath(os.path.dirname(__file__))

    # Secret key cho Flask
    SECRET_KEY = os.getenv('SECRET_KEY', 'S#perS3crEt_007')

    # Kết nối MySQL qua username và password
    SQLALCHEMY_DATABASE_URI = 'mysql://admin:1@localhost/iptables_management'
    SQLALCHEMY_TRACK_MODIFICATIONS = False  # Tắt việc theo dõi các thay đổi trong SQLAlchemy

    # Cấu hình cho quản lý assets
    ASSETS_ROOT = os.getenv('ASSETS_ROOT', '/static/assets')

class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_DURATION = 3600

class DebugConfig(Config):
    DEBUG = True

config_dict = {
    'Production': ProductionConfig,
    'Debug': DebugConfig
}
