# Student Tracking System

## Overview
This is a Flask-based web application for tracking student entries and exits. It provides security personnel with an interface to log student movements, analyze attendance trends, and manage student records.

## Features
- **User Authentication**: Admin and security personnel can log in.
- **Student Entry/Exit Logging**: Security can mark students as "entry" or "exit".
- **Dashboard**: Provides real-time insights into student presence.
- **CSV Upload**: Bulk student data import.
- **Analytics**: Visual reports using Matplotlib and Plotly.
- **Admin Management**: Manage students and logs.

## Technologies Used
- **Flask**: Web framework
- **Flask-Login**: User authentication
- **SQLAlchemy**: ORM for database management
- **Flask-Bcrypt**: Password hashing
- **Matplotlib & Plotly**: Data visualization
- **Pandas**: CSV processing

## Installation
### Prerequisites
- Python 3.x
- Flask & dependencies
- SQLite (or another DB setup if preferred)

### Setup Instructions
1. Clone the repository:
   ```sh
   git clone https://github.com/yourusername/student-tracking.git
   cd student-tracking
   ```
2. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```
3. Configure the database:
   ```sh
   flask db upgrade
   ```
4. Run the application:
   ```sh
   flask run
   ```
5. Access the web interface at:
   ```
   http://127.0.0.1:5000
   ```

## Usage
- **Login**: Security personnel and admins can log in.
- **Security View**: Enter an enrollment number to log student movements.
- **Dashboard**: Admins can view real-time stats.
- **Students List**: View and manage student records.
- **CSV Upload**: Bulk import student data.
- **Analytics**: View attendance trends over time.

## File Structure
```
├── app.py                  # Main Flask application
├── templates/              # HTML templates
├── static/                 # CSS, JS, and assets
├── instance/               # SQLite database
├── uploads/                # Uploaded CSV files
├── backups/                # Backup data storage
├── requirements.txt        # Dependencies
└── README.md               # Project documentation
```

## Future Enhancements
- Role-based access control
- Email notifications for unauthorized entries
- API endpoints for mobile integration
```python 
python -c "from app import app, db; app.app_context().push(); db.create_all()"
python -c "from app import app, db, bcrypt, User; app.app_context().push(); hashed_pw_sc = bcrypt.generate_password_hash('guard1234').decode('utf-8'); hashed_pw_ad = bcrypt.generate_password_hash('admin1234').decode('utf-8'); db.session.add(User(username='udit', password_hash=hashed_pw_ad, role='admin'));db.session.add(User(username='vdit', password_hash=hashed_pw_sc, role='security')); db.session.commit()"
```