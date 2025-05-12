from flask import Blueprint, render_template, request, redirect, url_for
from flask_login import login_user, logout_user, login_required
from apps import db, login_manager
from apps.authentication.forms import LoginForm
from apps.authentication.models import Users
from apps.authentication.util import verify_pass  # Giả sử bạn đã có hàm verify_pass

blueprint = Blueprint('authentication_blueprint', __name__)

class User:
    """ User class to interact with Flask-Login """
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(user_id):
    return Users.query.filter_by(username=user_id).first()

@blueprint.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if request.method == 'POST' and form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Tìm người dùng trong cơ sở dữ liệu MySQL
        user = Users.query.filter_by(username=username).first()

        if user and verify_pass(password, user.password_hash):  # Kiểm tra mật khẩu
            login_user(user)
            return redirect(url_for('home_blueprint.default'))  # Chuyển hướng tới trang chủ
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
