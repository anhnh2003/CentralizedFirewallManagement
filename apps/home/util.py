# apps/authentication/util.py
from flask import render_template
from functools import wraps
from flask_login import current_user

def role_required(role):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if current_user.role != role:
                return render_template('home/page-403.html')
            return f(*args, **kwargs)
        return wrapped
    return decorator
