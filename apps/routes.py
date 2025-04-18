from flask import redirect, url_for

@app.route('/')
def index():
    return redirect(url_for('authentication_blueprint.login'))