from flask import Blueprint, render_template, request, redirect, url_for
from flask_login import login_user, logout_user, login_required, current_user
from apps import db, login_manager
from apps.authentication.forms import LoginForm
from apps.authentication.models import Users
from apps.authentication.util import verify_pass  

blueprint = Blueprint('authentication_blueprint', __name__)


@blueprint.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST' and form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        print(f"Attempting login with username: {username} and password: {password}")  # Debugging line

        # Tìm người dùng trong cơ sở dữ liệu MySQL
        user = Users.query.filter_by(username=username).first()
        
        # Kiểm tra nếu có người dùng
        if user:
            print(f"User found: {user.username}")  # Debugging line

            # Kiểm tra mật khẩu
            if verify_pass(password, user.password_hash):
                print("Password match successful.")  # Debugging line
                login_user(user) # Đăng nhập người dùng
                print(user)
                print("get_id returned:", current_user.get_id())
                return redirect(url_for('home_blueprint.default'))  # Chuyển hướng tới trang chủ
            else:
                print("Password verification failed.")  # Debugging line
                print(f"Expected hash: {user.password_hash}")  # In ra hash kỳ vọng
        else:
            print("No user found with that username.")  # Debugging line

        # Nếu không thành công, hiển thị thông báo lỗi
        return render_template('accounts/login.html', form=form, msg='Invalid credentials')

    # Render lại form nếu phương thức không phải là POST hoặc không hợp lệ
    return render_template('accounts/login.html', form=form)


@blueprint.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('authentication_blueprint.login'))

@blueprint.route('/')
def index():
    return redirect(url_for('authentication_blueprint.login'))
