# -*- encoding: utf-8 -*-

from flask import Flask, redirect, url_for
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from importlib import import_module

db = SQLAlchemy()
login_manager = LoginManager()

# Cấu hình Flask-Login
login_manager.login_view = 'authentication_blueprint.login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'  # Optional

def register_extensions(app):
    db.init_app(app)
    login_manager.init_app(app)

    # Import tại đây để tránh circular import
    from apps.models import Users

    @login_manager.user_loader
    def load_user(user_id):
        return Users.query.get(int(user_id))

def register_blueprints(app):
    for module_name in ('authentication', 'home'):
        module = import_module(f'apps.{module_name}.routes')
        app.register_blueprint(module.blueprint, url_prefix=f'/{module_name}')

def create_app(config):
    app = Flask(__name__)
    app.config.from_object(config)

    register_extensions(app)
    register_blueprints(app)

    @app.route('/')
    def default():
        return redirect(url_for('authentication_blueprint.login'))

    return app
