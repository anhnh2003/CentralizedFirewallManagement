from flask import Blueprint, render_template, request, redirect, url_for
from flask_login import login_user, logout_user, login_required
from apps import db
from apps.authentication.models import User
from apps.authentication.forms import LoginForm

blueprint = Blueprint('authentication_blueprint', __name__)

@blueprint.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST' and form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Tìm người dùng trong cơ sở dữ liệu
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):  # Kiểm tra mật khẩu băm
            login_user(user)
            return redirect(url_for('home_blueprint.default'))
        else:
            return render_template('accounts/login.html', form=form, msg='Invalid credentials')
    
    return render_template('accounts/login.html', form=form)

@blueprint.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('authentication_blueprint.login'))

@blueprint.route('/')
def index():
    return redirect(url_for('authentication_blueprint.login'))
