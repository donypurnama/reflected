from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)

@app.route('/')
def main():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        post_user = request.form['username']
        role = request.form['role']

        # User Check
        # user = users.query.filter_by(username=post_user).first()

        if role=='admin':
            return redirect(url_for('dashboard'))
        elif role=='teacher':
            return redirect(url_for('teacher'))
        elif role=='student':
            return redirect(url_for('student'))
        elif post_user!='':
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/teacher')
def teacher():
    return render_template('teacher.html')

@app.route('/student')
def student():
    return render_template('student.html')

@app.route('/rating')
def rating():
    return render_template('rating.html')

@app.route('/rating_today')
def rating_today():
    return render_template('rating_today.html')

@app.route('/rating_month')
def rating_month():
    return render_template('rating_month.html')

@app.route('/rating_year')
def rating_year():
    return render_template('rating_year.html')

@app.route('/submitrating')
def submitrating():
    return render_template('submitrating.html')


@app.route('/logout')
def logout():
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=False)
