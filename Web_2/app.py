from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, and_
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.sql import func,desc
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta, timezone
import os
import plotly.express as px
import pandas as pd
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, emit
from flask_cors import CORS

basedir = os.path.abspath(os.path.dirname(__file__))


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(basedir, 'instance', 'student_tracking.db')}"
app.config['SECRET_KEY'] = 'thisissecret'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['BACKUP_FOLDER'] = 'backups'
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB limit for uploads

# When this code is entered instead of enrollement number, all students are marked as exit (who are currently inside)
SECRET_FORCE_EXIT_CODE = "787898"

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


CORS(app, resources={r"/*": {"origins": "*"}}) # For regular HTTP routes if needed
socketio = SocketIO(app, cors_allowed_origins="*") # Critical for SocketIO connections


## Important functions 
def get_current_time():
    return (datetime.now(timezone.utc) + timedelta(hours=5, minutes=30)).replace(microsecond=0)


def get_students_inside():
    # Subquery to get the latest log entry for each student
    latest_logs = db.session.query(
        Log.student_id,
        func.max(Log.timestamp).label('latest_timestamp')
    ).group_by(Log.student_id).subquery()
    
    # Join with logs to get the status and with students to get their details and timestamp
    students_inside = db.session.query(Student, Log.timestamp).join(
        Log, Student.student_id == Log.student_id
    ).join(
        latest_logs,
        (Log.student_id == latest_logs.c.student_id) &
        (Log.timestamp == latest_logs.c.latest_timestamp)
    ).filter(Log.status == 'entry').all()
    
    return students_inside
 

# Pushing all students out
def exiting_all():
    current_time = get_current_time()

    latest_logs = db.session.query(
        Log.student_id,
        func.max(Log.timestamp).label('latest_timestamp')
    ).group_by(Log.student_id).subquery()
    
    # Get all students whose latest status is 'entry'
    students_inside = db.session.query(Log.student_id).join(
        latest_logs, 
        and_(
            Log.student_id == latest_logs.c.student_id,
            Log.timestamp == latest_logs.c.latest_timestamp
        )
    ).filter(Log.status == 'entry').all()
    
    # Create exit logs for all these students
    for student in students_inside:
        new_exit_log = Log(
            student_id=student.student_id,
            timestamp=current_time,
            status='exit'
        )
        db.session.add(new_exit_log)
    
    # Commit all the new exit logs
    db.session.commit()


# Database Models
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False)

    def get_id(self):
        return str(self.user_id)


class Student(db.Model):
    __tablename__ = 'students'
    student_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    enrollment_number = db.Column(db.String(50), unique=True, nullable=False)
    department = db.Column(db.String(50))
    year = db.Column(db.Integer)
    batch = db.Column(db.String(50), nullable=False)
    section=db.Column(db.String(2), nullable=False)
    semester = db.Column(db.String(50), nullable=False)
    phone_no = db.Column(db.String(20), nullable=False)
    address = db.Column(db.String(200), nullable=False)

    def get_id(self):
    # Return the username as the unique identifier
        return self.student_id


class Log(db.Model):
    __tablename__ = 'logs'
    log_id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('students.student_id'), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default= get_current_time())
    status = db.Column(db.String(10), nullable=False)

    def get_id(self):
        # Return the id as the unique identifier
        return self.log_id


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# Routes
## Security View
@app.route('/security')
def security_view():
    return render_template('app2/security.html')

# Socket connection for security page
@socketio.on("enrollment_no_entered")
def handle_students(enrollment_number_str):
    enrollment_number = enrollment_number_str.strip().lstrip("0")

    student_result_data = None
    error_message = None
    students_inside_count = 0 # Default count

    # Trying database entry
    try:
        if enrollment_number == SECRET_FORCE_EXIT_CODE:
            exiting_all()
            # Emit signal to tell ALL connected clients that all students have left
            emit("exiting_all_processed", {'message': 'All students marked as exited.'}, broadcast=True)
            students_inside_count = 0 # Update count after exit
            # Emit the updated count to the specific client that triggered this
            emit("update_student_count", {'students_inside': students_inside_count})
            return # Stop further processing for this event

        student = Student.query.filter_by(enrollment_number=enrollment_number).first()

        if student:
            # Retrieve the most recent log entry for this student
            last_log = Log.query.filter_by(student_id=student.student_id)\
                              .order_by(Log.timestamp.desc())\
                              .first()
            
            # cooldown time, so that quick scan do not mark log incorrectly
            if (get_current_time().replace(tzinfo=None) - last_log.timestamp).seconds < 2:
                return

            # Toggle status
            new_status = 'exit' if last_log and last_log.status == 'entry' else 'entry'

            # Create a new log record.
            new_log = Log(
                student_id=student.student_id,
                status=new_status,
                timestamp=get_current_time()
            )
            db.session.add(new_log)
            db.session.commit()

            students_inside_count = len(get_students_inside())

            timestamp_str = new_log.timestamp.isoformat() if new_log.timestamp else None

            student_result_data = {
                'name': student.name,
                'enrollment_number': student.enrollment_number,
                'timestamp': timestamp_str,
                'status': new_status,
                'students_inside': students_inside_count # Include the latest count
            }
            # Emit the specific student data AND the updated count
            emit("update_student_data", student_result_data, broadcast=True)

        else:
            print(f"Invalid enrollment number: {enrollment_number}")
            error_message = f"Invalid enrollment number: {enrollment_number}"
            # Emit error back to the specific client
            emit("entry_error", {'message': error_message})
            # Still emit the current count even on error
            students_inside_count = len(get_students_inside())
            emit("update_student_count", {'students_inside': students_inside_count})


    except Exception as e:
        db.session.rollback() # Rollback in case of error during DB operations
        print(f"Error handling enrollment: {e}")
        error_message = "An internal error occurred."
         # Emit error back to the specific client
        emit("entry_error", {'message': error_message})
        # Try to get count even on error, might still be useful
        try:
             students_inside_count = len(get_students_inside())
             emit("update_student_count", {'students_inside': students_inside_count})
        except Exception:
             # If getting count fails too, emit 0 
             emit("update_student_count", {'students_inside': 'Error'})
   

## Home Route
@app.route('/')
def home():
    return redirect(url_for('security_view'))

## Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials', 'danger')
    return render_template('app2/login.html')

## Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

## Dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    # Get all students in latest order
    students = get_students_inside()[::-1]
    inside_count = len(students)
    return render_template('app2/dashboard.html', role=current_user.role, inside_count=inside_count, students = students, username=current_user.username)

## Log Entry (alternative entry point)
@app.route('/log_entry', methods=['POST'])
def log_entry():
    enrollment = request.form['enrollment']
    student = Student.query.filter_by(enrollment_number=enrollment).first()
    if student:
        last_log = Log.query.filter_by(student_id=student.student_id).order_by(Log.timestamp.desc()).first()
        new_status = 'exit' if last_log and last_log.status == 'entry' else 'entry'
        new_log = Log(student_id=student.student_id, status=new_status)
        db.session.add(new_log)
        db.session.commit()
        flash(f'Student {enrollment} marked as {new_status}', 'success')
    else:
        flash('Invalid enrollment number', 'danger')
    return redirect(url_for('dashboard'))

## Students List
@app.route('/students')
@login_required
def students():
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))
    students = Student.query.all()
    return render_template('app2/students.html', students=students, role=current_user.role)

## Add Individual Student
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
            year=int(request.form['year']),
            batch=request.form.get('batch'),
            semester=request.form.get('semester'),
            phone_no=request.form.get('phone_no'),
            address=request.form.get('address')
        )
        db.session.add(new_student)
        db.session.commit()
        flash('Student added successfully', 'success')
    except Exception as e:
        flash(f'Error adding student: {str(e)}', 'danger')
    return redirect(url_for('students'))



def validate_csv_data(df):
    """Validates that all required columns exist and contain valid data."""
    
    required_columns = ['name', 'enrollment_number', 'department', 'batch', 'year', 'semester', 'phone_no', 'address', 'section']
    
    # Normalize column names to lowercase and strip whitespace
    df.columns = [col.strip().lower() for col in df.columns]

    # Ensure all required columns are present
    missing_columns = [col for col in required_columns if col not in df.columns]
    if missing_columns:
        flash(f'Missing required columns: {", ".join(missing_columns)}', 'danger')
        return False

    # Drop empty rows
    df.dropna(how='all', inplace=True)

    for index, row in df.iterrows():
        print(f"Validating row {index}: {row.to_dict()}")  # Debugging log

        # Check for missing or invalid values in required columns
        for col in required_columns:
            if pd.isna(row[col]) or row[col] == '':
                flash(f'Missing value in column "{col}" at row {index}', 'danger')
                return False  # Reject entire file if any required value is missing

        # Validate enrollment_number (should be a number)
        if not str(row['enrollment_number']).isdigit():
            flash(f'Invalid enrollment number at row {index}', 'danger')
            return False
        
        # Validate phone_no (should be a 10-digit number)
        if not str(row['phone_no']).isdigit() or len(str(row['phone_no'])) != 10:
            flash(f'Invalid phone number at row {index}', 'danger')
            return False

    return True  # Data is valid

def process_csv(file_path):
    """Reads CSV, validates data, and inserts into database if all rows are valid."""
    try:
        df = pd.read_csv(file_path)

        if not validate_csv_data(df):
            flash('CSV file contains invalid data. No records were added.', 'danger')
            return False  # Stop processing

        for index, row in df.iterrows():
            student = Student.query.filter_by(enrollment_number=row['enrollment_number']).first()
            
            if not student:
                new_student = Student(
                    name=row['name'],
                    enrollment_number=row['enrollment_number'],
                    department=row['department'],
                    year=row['year'],
                    batch=row['batch'],
                    semester=row['semester'],
                    phone_no=row['phone_no'],
                    address=row['address'],
                    section=row['section'],
                )
                db.session.add(new_student)
            else:
                # Update existing student
                student.batch = row['batch']
                student.semester = row['semester']
                student.year = row['year']

        try:
            db.session.commit()
            flash('CSV file uploaded and processed successfully', 'success')
            return True
        except SQLAlchemyError as commit_error:
            db.session.rollback()
            flash(f'Error committing to DB: {str(commit_error)}', 'danger')
            return False

    except Exception as e:
        flash(f'Error processing CSV: {str(e)}', 'danger')
        return False

    finally:
        if os.path.exists(file_path):
            os.remove(file_path)

@app.route('/upload_csv', methods=['GET', 'POST'])
@login_required
def upload_csv():
    """Handles CSV file upload and processes student data."""
    
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        
        if not file.filename.endswith('.csv'):
            flash('Only CSV files are allowed', 'danger')
            return redirect(request.url)
        
        filename = secure_filename(file.filename)
        upload_folder = app.config['UPLOAD_FOLDER']
        
        # Ensure the uploads folder exists
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)
        
        file_path = os.path.join(upload_folder, filename)
        file.save(file_path)

        process_csv(file_path)
            # return redirect(url_for('dashboard'))  # Redirect on success

    return render_template('app2/upload_csv.html', role=current_user.role)


@app.route('/analytics')
@login_required
def analytics():
    # Get filter parameters
    batch = request.args.get('batch')
    semester = request.args.get('semester')
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')
    start_date = datetime.strptime(start_date_str, '%Y-%m-%d') if start_date_str else None
    end_date = datetime.strptime(end_date_str, '%Y-%m-%d') + timedelta(days=1) if end_date_str else None
    section=request.args.get('section')
    year=request.args.get('year')

    # Base Queries with Filters
    base_query = db.session.query(Log).join(Student, Student.student_id == Log.student_id)
    if batch:
        base_query = base_query.filter(Student.batch == batch)
    if semester:
        base_query = base_query.filter(Student.semester == semester)
    if section:
        base_query = base_query.filter(Student.section == section)
    if year:
        base_query = base_query.filter(Student.year == year)
    if start_date:
        base_query = base_query.filter(Log.timestamp >= start_date)
    if end_date:
        base_query = base_query.filter(Log.timestamp < end_date)

    # Total Entries and Exits
    total_entries = base_query.filter(Log.status == 'entry').count()
    total_exits = base_query.filter(Log.status == 'exit').count()

    # Unique Students
    unique_students = db.session.query(Log.student_id).distinct().count()


    # Students Currently Inside (not affected by date filters)
    subquery = db.session.query(Log.student_id, func.max(Log.timestamp).label('latest')).group_by(Log.student_id).subquery()
    students_inside = db.session.query(Log).join(subquery, (Log.student_id == subquery.c.student_id) & (Log.timestamp == subquery.c.latest)).filter(Log.status == 'entry').count()

    # Frequent Visitors
    frequent_visitors = db.session.query(
        Student.enrollment_number.label('enrollment'),
        func.count(Log.log_id).label('visit_count')
    ).join(Student, Log.student_id == Student.student_id)\
    .filter(Log.status == 'entry')\
    .group_by(Student.enrollment_number)\
    .order_by(desc('visit_count'))\
    .limit(5).all()

    # Hourly Activity Chart
    hour_col = func.strftime('%H', Log.timestamp).label('hour')
    hourly_data = base_query.group_by(hour_col, Log.status).with_entities(hour_col, Log.status, func.count().label('count')).all()
    df_hourly = pd.DataFrame(hourly_data, columns=['hour', 'status', 'count'])
    plot_hourly = px.bar(df_hourly, x='hour', y='count', color='status', title="Hourly Activity").to_html(full_html=False) if not df_hourly.empty else "<p>No data</p>"

    # Daily Activity Chart
    date_col = func.date(Log.timestamp).label('date')
    daily_data = base_query.group_by(date_col, Log.status).with_entities(date_col, Log.status, func.count().label('count')).all()
    df_daily = pd.DataFrame(daily_data, columns=['date', 'status', 'count'])
    plot_daily = px.line(df_daily, x='date', y='count', color='status', title="Daily Activity").to_html(full_html=False) if not df_daily.empty else "<p>No data</p>"

    # Entry vs Exit Pie Chart
    status_counts = base_query.group_by(Log.status).with_entities(Log.status, func.count().label('count')).all()
    df_status = pd.DataFrame(status_counts, columns=['status', 'count'])
    plot_pie = px.pie(df_status, names='status', values='count', title="Entry vs Exit").to_html(full_html=False) if not df_status.empty else "<p>No data</p>"

    # Monthly Trends
    month_col = func.strftime('%Y-%m', Log.timestamp).label('month')
    monthly_trends = base_query.filter(Log.status == 'entry').group_by(month_col).with_entities(month_col, func.count().label('count')).all()
    df_monthly = pd.DataFrame(monthly_trends, columns=['month', 'count'])
    plot_monthly = px.bar(df_monthly, x='month', y='count', title="Monthly Attendance Trends").to_html(full_html=False) if not df_monthly.empty else "<p>No data</p>"

    # Batch Comparison
    batch_comparison = db.session.query(Student.batch, func.count(Log.log_id).label('attendance_count')).join(Log, Student.student_id == Log.student_id).filter(Log.status == 'entry')
    if start_date:
        batch_comparison = batch_comparison.filter(Log.timestamp >= start_date)
    if end_date:
        batch_comparison = batch_comparison.filter(Log.timestamp < end_date)
    batch_comparison = batch_comparison.group_by(Student.batch).all()
    df_batch = pd.DataFrame(batch_comparison, columns=['batch', 'attendance_count'])
    plot_batch = px.bar(df_batch, x='batch', y='attendance_count', title="Attendance by Batch").to_html(full_html=False) if not df_batch.empty else "<p>No data</p>"

    # Filter Options
    batches = [b[0] for b in db.session.query(Student.batch).distinct().all() if b[0]]
    semesters = [s[0] for s in db.session.query(Student.semester).distinct().all() if s[0]]
    sections = [s[0] for s in db.session.query(Student.section).distinct().all() if s[0]]
    years = [s[0] for s in db.session.query(Student.year).distinct().all() if s[0]]

    return render_template(
        'app2/analytics.html',
        total_entries=total_entries,
        total_exits=total_exits,
        unique_students=unique_students,
        students_inside=students_inside,
        frequent_visitors=frequent_visitors,
        plot_hourly=plot_hourly,
        plot_daily=plot_daily,
        plot_pie=plot_pie,
        plot_monthly=plot_monthly,
        plot_batch=plot_batch,
        role=current_user.role,
        batches=batches,
        sections=sections,
        semesters=semesters,
        years=years,
        selected_batch=batch,
        selected_semester=semester,
        selected_start_date=start_date_str,
        selected_end_date=end_date_str
    )

# Run the App
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    # app.run(debug=True)
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)