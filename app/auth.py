from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user
from .models import User
from . import mysql, login_manager
import MySQLdb.cursors
from werkzeug.security import check_password_hash

auth = Blueprint('auth', __name__)

@login_manager.user_loader
def load_user(user_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user_data = cursor.fetchone()
    cursor.close()
    if user_data:
        return User(user_data['id'], user_data['username'], user_data['password'], user_data['role'])
    return None


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Fetch user by username only
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user_data = cursor.fetchone()
        cursor.close()

        # Check if user exists and password is correct
        if user_data and check_password_hash(user_data['password'], password):
            if user_data['role'] == 'user':
                flash("You don't have any permission to visit the web app.", "danger")
                return redirect(url_for('auth.login'))
            user = User(user_data['id'], user_data['username'], user_data['password'], user_data['role'])
            login_user(user)
            flash("Logged in successfully.", "success")
            return redirect(url_for('main.dashboard'))  # You can still separate redirects by role if needed

        else:
            flash("Invalid username or password.", "danger")
            return redirect(url_for('auth.login'))

    return render_template('login.html')

@auth.route('/logout')
def logout():
    logout_user()
    flash("Logged out successfully.", "success")
    return redirect(url_for('auth.login'))
