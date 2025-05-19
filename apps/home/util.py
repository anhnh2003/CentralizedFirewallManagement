# apps/authentication/util.py
from flask import render_template
from functools import wraps
from flask_login import current_user

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not any(current_user.role == r for r in roles):
                return render_template('home/page-403.html')
            return f(*args, **kwargs)
        return wrapped
    return decorator