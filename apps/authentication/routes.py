from flask import Blueprint, render_template, request, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
import pam
from apps import login_manager
from apps.authentication.forms import LoginForm

blueprint = Blueprint('authentication_blueprint', __name__)

pam_auth = pam.pam()

class User(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

@blueprint.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST' and form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        if pam_auth.authenticate(username, password):
            user = User(username)
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