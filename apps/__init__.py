# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from flask import Flask, redirect, url_for
from flask_login import LoginManager

from importlib import import_module



login_manager = LoginManager()
# Specify the login view (redirect for unauthorized users)
login_manager.login_view = 'authentication_blueprint.login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'  # Optional: category for flash messages

def register_extensions(app):
    login_manager.init_app(app)


def register_blueprints(app):
    for module_name in ('authentication', 'home'):
        module = import_module('apps.{}.routes'.format(module_name))
        app.register_blueprint(module.blueprint, url_prefix='/{}'.format(module_name))



def create_app(config):
    app = Flask(__name__)
    app.config.from_object(config)
    register_extensions(app)
    register_blueprints(app)
    @app.route('/')
    def default():
        return redirect(url_for('authentication_blueprint.login'))
    return app
