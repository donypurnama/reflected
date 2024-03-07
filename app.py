from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, DecimalField, TextAreaField
from wtforms.validators import DataRequired, Length, NumberRange
from flask_bcrypt import Bcrypt
from datetime import datetime  # Import datetime module
from wtforms.fields import DateTimeField
from sqlalchemy.orm import aliased
from flask import jsonify
from sqlalchemy import extract
from sqlalchemy import func

import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'reflected'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.path.abspath(os.path.dirname(__file__)), 'reflected.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
bootstrap = Bootstrap(app)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Model untuk data pengguna
class Users(db.Model):
      __tablename__ = 'users'
      id = db.Column(db.Integer, primary_key=True, autoincrement=True)
      username = db.Column(db.Text)
      name = db.Column(db.Text)
      role = db.Column(db.Text)
      password = db.Column(db.Text)
      subjects = db.Column(db.Text)
      subjects_id = SelectField('Subjects', coerce=int)  # Update the field name

      def set_password(self, password):
        self.password = generate_password_hash(password)

      def check_password(self, password):
        return check_password_hash(self.password, password)

# Model untuk data ratings
class Ratings(db.Model):
   __tablename__ = 'ratings'
   id = db.Column(db.Integer, primary_key=True, autoincrement=True)
   student_id = db.Column(db.Integer, nullable=False)
   student_name = db.Column(db.Text)
   teacher_id = db.Column(db.Integer, nullable=False)
   teacher_name = db.Column(db.Text)
   rating = db.Column(db.Numeric, nullable=False)
   created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
   comments = db.Column(db.Text)
   created_by = db.Column(db.Integer, nullable=False)

# Model untuk subjects
class Subjects(db.Model):
    __tablename__ = 'subjects'
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.Text)

# Model untuk grades
class Grades(db.Model):
    __tablename__ = 'grades'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text)

# Formulir untuk manajemen pengguna
class UserForm(FlaskForm):
      username = StringField('Username', validators=[DataRequired()])
      password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
      role = SelectField('Role', choices=[('admin', 'Admin'), ('student', 'Student'), ('teacher', 'Teacher')], validators=[DataRequired()])
      name = StringField('Full Name')
      subjects = StringField('Subjects')
      submit = SubmitField('Submit User')

# Formulir untuk edit pengguna
class EditUserForm(FlaskForm):
    password = PasswordField('New Password', validators=[Length(min=6)])
    submit = SubmitField('Update')

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
   if request.method == 'POST':
      username = request.form['username']
      password = request.form['password']

      user = Users.query.filter_by(username=username).first()

      if user and user.check_password(password):

         flash('Login berhasil!', 'success')

         # Store user information in the session
         session['user_id'] = user.id
         session['username'] = user.username
         session['role'] = user.role

         # Mengambil nilai dari kolom 'role'
         role = user.role

         if role=='admin':
            return redirect(url_for('dashboard'))
         elif role=='teacher':
            return redirect(url_for('teacher'))
         elif role=='student':
            return redirect(url_for('student'))

      else:
         # Login gagal
         flash('Username atau password salah', 'danger')

   return render_template('login.html', error=None)

@app.route('/dashboard')
def dashboard():
   # Retrieve user information from the session
   user_id = session.get('user_id')
   username = session.get('username')
   role = session.get('role')

   # select average rating from all student 
   average_rating = db.session.query(func.avg(Ratings.rating).label('average_rating')).scalar()

   count_rating = db.session.query(func.count(Ratings.rating).label('count_rating')).scalar()

   count_students = Users.query.filter_by(role='student').count()

   return render_template('dashboard.html', userid=user_id, username=username, role=role, average_rating=average_rating, count_rating=count_rating, count_students=count_students)

@app.route('/teacher')
def teacher():
   # Retrieve user information from the session
   user_id = session.get('user_id')
   username = session.get('username')
   role = session.get('role')

   # select average rating from teacher login 
   average_rating = db.session.query(
      func.avg(Ratings.rating).label('average_rating')
   ).filter(
      Ratings.teacher_id == user_id
   ).scalar()

   count_rating = db.session.query(func.count().label('count_rating')).filter(Ratings.teacher_id == user_id).scalar()

   count_students = Users.query.filter_by(role='student').count()

   return render_template('teacher.html', userid=user_id, username=username, role=role, average_rating=average_rating, count_rating=count_rating, count_students=count_students)

@app.route('/student')
def student():
   # Retrieve user information from the session
   user_id = session.get('user_id')
   username = session.get('username')
   role = session.get('role')

    

   # select average rating from student login 
   ratings_users = db.session.query(
      Ratings.teacher_id,
      Ratings.teacher_name,
      Users.subjects,
      func.avg(Ratings.rating).label('average_rating')
   ).outerjoin(
      Users, Ratings.teacher_id == Users.id
   ).filter(
      Ratings.created_by == user_id
   ).group_by(
      Ratings.teacher_id
   ).all()

   return render_template('student.html', userid=user_id, username=username, role=role, ratings_users=ratings_users)

@app.route('/rating')
def rating():
   user_id = session.get('user_id')
   username = session.get('username')
   role = session.get('role')
   return render_template('rating.html', userid=user_id, username=username, role=role)

@app.route('/rating_today')
def rating_today():
   user_id = session.get('user_id')
   username = session.get('username')
   role = session.get('role')
   return render_template('rating_today.html', userid=user_id, username=username, role=role)

@app.route('/rating_month')
def rating_month():
   user_id = session.get('user_id')
   username = session.get('username')
   role = session.get('role')
   return render_template('rating_month.html', userid=user_id, username=username, role=role)

@app.route('/rating_year')
def rating_year():
   user_id = session.get('user_id')
   username = session.get('username')
   role = session.get('role')
   return render_template('rating_year.html', userid=user_id, username=username, role=role)

@app.route('/submitrating')
def submitrating():
   user_id = session.get('user_id')
   username = session.get('username')
   role = session.get('role')
   return render_template('a_add_rating.html', userid=user_id, username=username, role=role)

# Route untuk menampilkan semua pengguna
@app.route('/users')
def index():
   user_id = session.get('user_id')
   username = session.get('username')
   role = session.get('role')
   users = Users.query.all()
   return render_template('a_list_students.html', users=users, userid=user_id, username=username, role=role)

# Route untuk menambah pengguna baru
@app.route('/add_users', methods=['POST'])
def add_users():
    
   username = request.form['username']
   password = request.form['password']
   hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

   name = request.form['name']
   role = request.form['role']
   subjects_id = request.form['subjects_id']
   
   if subjects_id  == 0:
      f_subject = Subjects.query.filter_by(id=subjects_id).first()
      subjects = f_subject.subject
   else:
      subjects = 'student'

   new_user = Users(username=username, password=hashed_password, role=role, name=name, subjects_id=subjects_id, subjects=subjects)
   db.session.add(new_user)
   db.session.commit()

   try:
      db.session.add(new_user)
      db.session.commit()
      
      # Flash message for successful user addition
      flash(f'User {username} added successfully!', 'success')
      
      # Redirect to a relevant page (e.g., users list)
      return redirect('/users')
   except Exception as e:
      
      # Flash message for an error during user addition
      flash(f'Error adding user: {str(e)}', 'danger')
      # Redirect to a relevant page (e.g., users list)
      return redirect('/users')


# Route untuk menambah pengguna baru
@app.route('/user_new', methods=['GET', 'POST'])
def add_user():
   form = UserForm()

    # Ambil data dari database table subjects
   subjects_lists = Subjects.query.all()

   ratings = Ratings.query.all()
     # Ambil data dari database berdasarkan kriteria role = 'student'
   students = Users.query.filter_by(role='student').all()
    # Ambil data dari database berdasarkan kriteria role = 'teacher'
   teachers = Users.query.filter_by(role='teacher').all()
   #  if form.validate_on_submit():
   #       username = form.username.data
   #       password = form.password.data
   #       hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

   #       role = form.role.data
   #       name = form.name.data
   #       subjects = form.subjects.data

   #       new_user = Users(username=username, password=hashed_password, role=role, name=name, subjects=subjects)
   #       db.session.add(new_user)
   #       db.session.commit()

   #       flash(f'User {username} berhasil ditambahkan!', 'success')
   #       return redirect(url_for('index'))

   #  return render_template('a_add_user.html', form=form, subjects_lists=subjects_lists)
   return render_template('a_add_user.html', ratings=ratings, students=students, teachers=teachers, subjects_lists=subjects_lists)

# Route untuk mengedit pengguna
@app.route('/edit_user/<int:id>', methods=['GET', 'POST'])
def edit_user(id):
    user = Users.query.get(id)
    form = EditUserForm()

    if form.validate_on_submit():
        new_password = form.password.data
        if new_password:
            user.password_hash = generate_password_hash(new_password, method='pbkdf2:sha256')
            db.session.commit()
            flash(f'Password pengguna {user.username} berhasil diubah!', 'success')
        else:
            flash('Password baru tidak boleh kosong!', 'danger')

    return render_template('edit_user.html', user=user, form=form)

# Route untuk menghapus pengguna
@app.route('/delete_user/<int:id>')
def delete_user(id):
    user = Users.query.get(id)
    db.session.delete(user)
    db.session.commit()
    flash(f'User {user.username} berhasil dihapus!', 'success')
    return redirect(url_for('index'))

# Route untuk menampilkan daftar ratings
@app.route('/ratings')
def list_rating():
    ratings = Ratings.query.all()
     # Ambil data dari database berdasarkan kriteria role = 'student'
    students = Users.query.filter_by(role='student').all()
    # Ambil data dari database berdasarkan kriteria role = 'teacher'
    teachers = Users.query.filter_by(role='teacher').all()

     # Query untuk melakukan join antara tabel Ratings dan Users dengan menggunakan filter
    ratings_users = db.session.query(Ratings, Users)\
        .join(Users, Ratings.student_id == Users.id)\
        .all()

    return render_template('a_index_ratings.html', ratings=ratings, students=students, teachers=teachers, ratings_users=ratings_users)

# Route untuk menambah ratings baru
@app.route('/add_ratings', methods=['POST'])
def add_ratings():
    student_id_content = request.form['student_id']
    f_student = Users.query.filter_by(id=student_id_content).first()
    student_name = f_student.name

    teacher_id_content = request.form['teacher_id']
    f_teacher = Users.query.filter_by(id=teacher_id_content).first()
    teacher_name = f_teacher.name

    rating_content = request.form['rating']
    created_at_content = datetime.utcnow()
    comments_at_content = request.form['comments']
    created_by = session.get('user_id')
    new_rating = Ratings(student_id=student_id_content, student_name=student_name, teacher_id=teacher_id_content, teacher_name=teacher_name, rating=rating_content, created_at=created_at_content, comments=comments_at_content, created_by=created_by)

    try:
        db.session.add(new_rating)
        db.session.commit()
        return redirect('/ratings')
    except Exception as e:
        print(e)
        return 'Terjadi kesalahan saat menambah rating baru.'

# Route untuk menghapus data ratings
@app.route('/delete_rating/<int:id>')
def delete_rating(id):
    rating_to_delete = Ratings.query.get(id)

    try:
         db.session.delete(rating_to_delete)
         db.session.commit()
         flash(f'Subject berhasil dihapus!', 'success')
         return redirect(url_for('list_rating'))
    except:
        return 'Terjadi kesalahan saat menghapus rating.'


# Route untuk menampilkan daftar subjects
@app.route('/subjects')
def list_subject():
    subjects = Subjects.query.all()
    return render_template('a_index_subjects.html', subjects=subjects)

# Route untuk menambah subjects baru
@app.route('/add_subjects', methods=['POST'])
def add_subjects():
    name_content = request.form['name']
    new_subject = Subjects(subject=name_content)

    try:
        db.session.add(new_subject)
        db.session.commit()
        return redirect('/subjects')
    except:
        return 'Terjadi kesalahan saat menambah tugas baru.'

# Route untuk menghapus data subjects
@app.route('/delete_subject/<int:id>')
def delete_subject(id):
    subject_to_delete = Subjects.query.get(id)

    try:
         db.session.delete(subject_to_delete)
         db.session.commit()
         # return redirect('/')
         flash(f'Subject berhasil dihapus!', 'success')
         return redirect(url_for('list_subject'))
    except:
        return 'Terjadi kesalahan saat menghapus tugas.'

# Route untuk menampilkan daftar grades
@app.route('/grades')
def list_grades():
    grades = Grades.query.all()
    return render_template('a_index_grades.html', grades=grades)

# Route untuk menambah grades baru
@app.route('/add_grades', methods=['POST'])
def add_grades():
      name_content = request.form['name']
      new_grade = Grades(name=name_content)

      try:
        db.session.add(new_grade)
        db.session.commit()
        return redirect('/grades')
      except:
        return 'Terjadi kesalahan saat menambah tugas baru.'

# Route untuk menghapus data subjects
@app.route('/delete_grade/<int:id>')
def delete_grade(id):
    grade_to_delete = Grades.query.get(id)

    try:
         db.session.delete(grade_to_delete)
         db.session.commit()
         flash(f'Grades berhasil dihapus!', 'success')
         return redirect(url_for('list_grades'))
    except:
        return 'Terjadi kesalahan saat menghapus tugas.'

## STUDENT SECTION 
# Route untuk menampilkan daftar ratings, berdasauser
@app.route('/studentratings')
def list_rating_s():
   user_id = session.get('user_id')
   username = session.get('username')
   role = session.get('role')

   ratings = Ratings.query.all()
     # Ambil data dari database berdasarkan kriteria role = 'student'
   students = Users.query.filter_by(id=user_id).all()
    # Ambil data dari database berdasarkan kriteria role = 'teacher'
   teachers = Users.query.filter_by(role='teacher').all()

   # select rating filter user_id login
   ratings_users = db.session.query(Ratings, Users)\
    .join(Users, Ratings.teacher_id == Users.id)\
    .filter(Ratings.created_by == user_id)\
    .all()

   return render_template('s_index_ratings.html', userid=user_id, username=username, role=role, ratings=ratings, students=students, teachers=teachers, ratings_users=ratings_users)


# Route untuk menampilkan daftar ratings, today
@app.route('/student-today-ratings')
def today_rating_s():
   user_id = session.get('user_id')
   username = session.get('username')
   role = session.get('role')

   # select rating filter user_id login
   ratings_users = db.session.query(Ratings, Users)\
      .join(Users, Ratings.teacher_id == Users.id)\
      .filter(Ratings.created_by == user_id)\
      .filter(extract('day', Ratings.created_at) == datetime.now().day) \
      .all()
   
   return render_template('s_index_today_ratings.html', userid=user_id, username=username, role=role, ratings_users=ratings_users)


# Route untuk menampilkan daftar ratings, month
@app.route('/student-month-ratings')
def monthly_rating_s():
   user_id = session.get('user_id')
   username = session.get('username')
   role = session.get('role')

   # select rating filter user_id login
   ratings_users = db.session.query(Ratings, Users)\
    .join(Users, Ratings.teacher_id == Users.id)\
    .filter(Ratings.created_by == user_id)\
    .filter(extract('month', Ratings.created_at) == datetime.now().month) \
    .all()
   
   return render_template('s_index_month_ratings.html', userid=user_id, username=username, role=role, ratings_users=ratings_users)

# Route untuk menampilkan daftar ratings, yearly
@app.route('/student-year-ratings')
def yearly_rating_s():
   user_id = session.get('user_id')
   username = session.get('username')
   role = session.get('role')

   # select rating filter user_id login
   ratings_users = db.session.query(Ratings, Users)\
   .join(Users, Ratings.teacher_id == Users.id)\
   .filter(Ratings.created_by == user_id)\
   .filter(extract('year', Ratings.created_at) == datetime.now().year) \
   .all()
   
   return render_template('s_index_year_ratings.html', userid=user_id, username=username, role=role, ratings_users=ratings_users)



# TEACHER SECTION 


# Route untuk menampilkan daftar ratings, today
@app.route('/teacher-today-ratings')
def today_rating_t():
   user_id = session.get('user_id')
   username = session.get('username')
   role = session.get('role')

   # Mengambil tanggal hari ini
   today_date = datetime.today().date()

   # Mendapatkan tanggal hari ini dalam format yang sesuai dengan basis data Anda
   today_date = datetime.now().strftime("%Y-%m-%d")

   # Query SQLAlchemy untuk mendapatkan data yang diinginkan
   ratings_users = Ratings.query.filter_by(teacher_id=user_id).with_entities(
      Ratings.id,
      Ratings.student_id,
      Ratings.student_name,
      Ratings.rating,
      Ratings.created_at,
      Ratings.comments
   ).all()
   
   return render_template('t_index_today_ratings.html', userid=user_id, username=username, role=role, ratings_users=ratings_users)


# Route untuk menampilkan daftar ratings, month
@app.route('/teacher-month-ratings')
def monthly_rating_t():
   user_id = session.get('user_id')
   username = session.get('username')
   role = session.get('role')

   # select rating filter user_id login
   ratings_users = db.session.query(Ratings, Users)\
    .join(Users, Ratings.teacher_id == Users.id)\
    .filter(Ratings.created_by == user_id)\
    .filter(extract('month', Ratings.created_at) == datetime.now().month) \
    .all()
   
   return render_template('t_index_month_ratings.html', userid=user_id, username=username, role=role, ratings_users=ratings_users)

# Route untuk menampilkan daftar ratings, yearly
@app.route('/teacher-year-ratings')
def yearly_rating_t():
   user_id = session.get('user_id')
   username = session.get('username')
   role = session.get('role')

   # select rating filter user_id login
   ratings_users = db.session.query(Ratings, Users)\
   .join(Users, Ratings.teacher_id == Users.id)\
   .filter(Ratings.created_by == user_id)\
   .filter(extract('year', Ratings.created_at) == datetime.now().year) \
   .all()
   
   return render_template('t_index_year_ratings.html', userid=user_id, username=username, role=role, ratings_users=ratings_users)







# Route to get the teacher's name by teacher_id
@app.route('/get_teacher_name/<int:teacher_id>')
def get_teacher_name(teacher_id):
    teacher_name = get_teacher_name_by_id(teacher_id)

    # Return the teacher's name as JSON response
    return jsonify({'teacher_name': teacher_name})

# Route untuk logout
@app.route('/logout')
def logout():
    return redirect(url_for('login'))

if __name__ == '__main__':
   app.run(debug=False)
