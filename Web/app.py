from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func,distinct

from flask_bcrypt import Bcrypt
from datetime import datetime

from io import BytesIO
import base64
import os

import matplotlib.pyplot as plt
import plotly.express as px
import pandas as pd




app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////home/udit/Documents/Github/003_Student_tracking/Web/instance/student_tracking.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['BACKUP_FOLDER'] = 'backups'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)

# Database Models
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False)

    def get_id(self):
        # Return the username as the unique identifier
        return self.user_id

class Student(db.Model):
    __tablename__ = 'students'
    student_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    enrollment_number = db.Column(db.String(50), unique=True, nullable=False)
    department = db.Column(db.String(50))
    year = db.Column(db.Integer)

    def get_id(self):
        # Return the username as the unique identifier
        return self.student_id

class Log(db.Model):
    __tablename__ = 'logs'
    log_id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('students.student_id'), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    status = db.Column(db.String(10), nullable=False)

    def get_id(self):
        # Return the id as the unique identifier
        return self.log_id

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



@app.route('/security', methods=['GET', 'POST'])

def security_view():
    if request.method == 'GET':
        return render_template('security.html')


    if request.method == 'POST':
        enrollment_number = request.form.get('enrollment')

        student = Student.query.filter_by(enrollment_number=enrollment_number).first()
            
        if student:
            last_log = Log.query.filter_by(student_id=student.student_id)\
                        .order_by(Log.timestamp.desc())\
                        .first()
            
            new_status = 'exit' if last_log and last_log.status == 'entry' else 'entry'
            
            new_log = Log(student_id=student.student_id, status=new_status)
            db.session.add(new_log)
            db.session.commit()
            flash(f'Student {enrollment_number} marked as {new_status}',category="success")
        else:
            flash('Invalid enrollment number',category="danger")


    # Fetch last 10 logs
    logs = db.session.execute(
        db.select(Log, Student)
        .join(Student)
        .order_by(Log.timestamp.desc())
        .limit(10)
    ).all()

    # Count students currently inside (Using ORM correctly)
    subquery = db.session.query(
        Log.student_id, func.max(Log.timestamp).label('max_timestamp')
    ).group_by(Log.student_id).subquery()

    students_inside = db.session.query(Log.student_id).join(
        subquery, (Log.student_id == subquery.c.student_id) & (Log.timestamp == subquery.c.max_timestamp)
    ).filter(Log.status == 'entry').distinct().count()

    return render_template('security.html', logs=logs, students_inside=students_inside, username="Security")
    

# Routes
@app.route('/')
def home():
    return redirect(url_for('security_view'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    inside_count = db.session.query(Log.student_id)\
                   .distinct()\
                   .filter(Log.status == 'entry')\
                   .count()
    
    return render_template('dashboard.html',
                         role=current_user.role,
                         inside_count=inside_count,
                         username=current_user.username)

@app.route('/log_entry', methods=['POST'])
def log_entry():
    enrollment = request.form['enrollment']
    student = Student.query.filter_by(enrollment_number=enrollment).first()
    
    if student:
        last_log = Log.query.filter_by(student_id=student.student_id)\
                      .order_by(Log.timestamp.desc())\
                      .first()
        
        new_status = 'exit' if last_log and last_log.status == 'entry' else 'entry'
        
        new_log = Log(student_id=student.student_id, status=new_status)
        db.session.add(new_log)
        db.session.commit()
        flash(f'Student {enrollment} marked as {new_status}')
    else:
        flash('Invalid enrollment number')
    
    return redirect(url_for('dashboard'))


@app.route('/students')
@login_required
def students():
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))
    
    students = Student.query.all()
    return render_template('students.html', students=students,role=current_user.role)

@app.route('/add_student', methods=['POST'])
@login_required
def add_student():
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))
    
    try:
        new_student = Student(
            name=request.form['name'],
            enrollment_number=request.form['enrollment'],
            department=request.form['department'],
            year=int(request.form['year'])
        )
        db.session.add(new_student)
        db.session.commit()
        flash('Student added successfully')
    except:
        flash('Error adding student')
    
    return redirect(url_for('students'))




@app.route('/analytics')
@login_required
def analytics():
    # 1. Total Entries & Exits
    total_entries = db.session.query(func.count()).filter(Log.status == 'entry').scalar() or 0
    total_exits = db.session.query(func.count()).filter(Log.status == 'exit').scalar() or 0
    unique_students = db.session.query(func.count(distinct(Log.student_id))).scalar() or 0

    # 2. Most Frequent Visitors (Top 5)
    frequent_visitors = db.session.query(
        Log.student_id, func.count().label('visit_count')
    ).group_by(Log.student_id).order_by(func.count().desc()).limit(5).all()

    # 3. Peak Entry & Exit Hours
    peak_hours = db.session.query(
        func.strftime('%H', Log.timestamp).label('hour'),
        Log.status,
        func.count().label('count')
    ).group_by('hour', Log.status).order_by(func.count().desc()).limit(5).all()

    # 4. Students Currently Inside
    subquery = db.session.query(
        Log.student_id, func.max(Log.timestamp).label('latest')
    ).group_by(Log.student_id).subquery()

    students_inside = db.session.query(Log).join(
        subquery, (Log.student_id == subquery.c.student_id) & (Log.timestamp == subquery.c.latest)
    ).filter(Log.status == 'entry').count()

    # 5. Hourly Activity Chart
    hourly_data = db.session.query(
        func.strftime('%H', Log.timestamp).label('hour'),
        Log.status,
        func.count().label('count')
    ).group_by('hour', Log.status).all()

    df_hourly = pd.DataFrame(hourly_data, columns=['hour', 'status', 'count'])
    plot_hourly = px.bar(df_hourly, x='hour', y='count', color='status',
                         labels={'hour': 'Hour of Day', 'count': 'Entries/Exits'},
                         title="Hourly Student Activity",
                         barmode='group').to_html(full_html=False) if not df_hourly.empty else "<p>No data available.</p>"

    # 6. Daily Activity Chart
    daily_data = db.session.query(
        func.date(Log.timestamp).label('date'),
        Log.status,
        func.count().label('count')
    ).group_by('date', Log.status).all()

    df_daily = pd.DataFrame(daily_data, columns=['date', 'status', 'count'])
    plot_daily = px.line(df_daily, x='date', y='count', color='status',
                         labels={'date': 'Date', 'count': 'Entries/Exits'},
                         title="Daily Entry/Exit Trend").to_html(full_html=False) if not df_daily.empty else "<p>No data available.</p>"

    # 7. Entry vs Exit Pie Chart
    status_counts = db.session.query(Log.status, func.count().label('count')).group_by(Log.status).all()
    df_status = pd.DataFrame(status_counts, columns=['status', 'count'])
    plot_pie = px.pie(df_status, names='status', values='count', title="Entry vs Exit Distribution").to_html(full_html=False) if not df_status.empty else "<p>No data available.</p>"

    # 8. Fetch Last 50 Logs
    logs = db.session.execute(db.select(Log).order_by(Log.timestamp.desc()).limit(50)).scalars().all()

    return render_template(
        'analytics.html',
        total_entries=total_entries,
        total_exits=total_exits,
        unique_students=unique_students,
        students_inside=students_inside,
        frequent_visitors=frequent_visitors,
        peak_hours=peak_hours,
        plot_hourly=plot_hourly,
        plot_daily=plot_daily,
        plot_pie=plot_pie,
        role=current_user.role,
        logs=logs
    )



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)



# python -c "from app import app, db; app.app_context().push(); db.create_all()"
# python -c "from app import app, db, bcrypt, User; app.app_context().push(); hashed_pw_sc = bcrypt.generate_password_hash('guard1234').decode('utf-8'); hashed_pw_ad = bcrypt.generate_password_hash('admin1234').decode('utf-8'); db.session.add(User(username='udit', password_hash=hashed_pw_ad, role='admin'));db.session.add(User(username='vdit', password_hash=hashed_pw_sc, role='security')); db.session.commit()"