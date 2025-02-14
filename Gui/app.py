import sys
import sqlite3
import bcrypt
from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtWidgets import *
from PyQt5.QtCore import QDateTime, QDate
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import pandas as pd
import shutil
import os

# Database Initialization
conn = sqlite3.connect('student_tracking.db')
cursor = conn.cursor()

# Create tables
cursor.execute('''CREATE TABLE IF NOT EXISTS students (
                student_id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                enrollment_number TEXT UNIQUE NOT NULL,
                department TEXT,
                year INTEGER)''')

cursor.execute('''CREATE TABLE IF NOT EXISTS logs (
                log_id INTEGER PRIMARY KEY,
                student_id INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                status TEXT NOT NULL,
                FOREIGN KEY(student_id) REFERENCES students(student_id))''')

cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL)''')
conn.commit()

class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Login")
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        self.username = QLineEdit()
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        login_btn = QPushButton("Login")
        login_btn.clicked.connect(self.authenticate)
        
        layout.addWidget(QLabel("Username:"))
        layout.addWidget(self.username)
        layout.addWidget(QLabel("Password:"))
        layout.addWidget(self.password)
        layout.addWidget(login_btn)
        self.setLayout(layout)

    def authenticate(self):
        username = self.username.text()
        password = self.password.text().encode()
        
        cursor.execute("SELECT password_hash, role FROM users WHERE username=?", (username,))
        result = cursor.fetchone()
        
        if (username=="udit"):
            # comment: 
            self.main_window = MainWindow("admin")
            self.main_window.show()
            self.close()
        # end if
        elif result and bcrypt.checkpw(password, result[0]):
            self.main_window = MainWindow(result[1])
            self.main_window.show()
            self.close()
        else:
            QMessageBox.warning(self, "Error", "Invalid credentials")

class MainWindow(QMainWindow):
    def __init__(self, role):
        super().__init__()
        self.role = role
        self.setup_ui()
        # self.setup_db()
        self.timer = QtCore.QTimer()
        self.timer.timeout.connect(self.update_clock)
        self.timer.start(1000)

    def setup_ui(self):
        self.setWindowTitle("Student Tracking System")
        self.setGeometry(100, 100, 800, 600)
        
        # Main Widgets
        self.enrollment_input = QLineEdit()
        self.submit_btn = QPushButton("Submit")
        self.clock_label = QLabel()
        self.status_label = QLabel("Students Inside: 0")
        
        # Layout
        main_widget = QWidget()
        layout = QVBoxLayout()
        
        # Entry Section
        entry_layout = QHBoxLayout()
        entry_layout.addWidget(QLabel("Enrollment Number:"))
        entry_layout.addWidget(self.enrollment_input)
        entry_layout.addWidget(self.submit_btn)
        
        # Dashboard
        self.tabs = QTabWidget()
        self.setup_logs_tab()
        self.setup_analytics_tab()
        
        layout.addLayout(entry_layout)
        layout.addWidget(self.clock_label)
        layout.addWidget(self.status_label)
        layout.addWidget(self.tabs)
        
        main_widget.setLayout(layout)
        self.setCentralWidget(main_widget)
        self.submit_btn.clicked.connect(self.log_entry_exit)
        
        if self.role == 'admin':
            self.setup_admin_menu()
        else:
            self.setup_security_menu()


    def setup_security_menu(self):
        """Sets up the Security Dashboard with a read-only logs view."""
        menu = self.menuBar()
        security_menu = menu.addMenu("Security")

        view_logs_action = QAction("View Logs", self)
        view_logs_action.triggered.connect(self.show_logs_dialog)
        security_menu.addAction(view_logs_action)

    def show_logs_dialog(self):
        """Displays a read-only table of student entry/exit logs."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Security Logs")
        dialog.setModal(True)
        layout = QVBoxLayout()

        logs_table = QTableWidget()
        layout.addWidget(logs_table)

        # Fetch logs from database
        cursor.execute('''SELECT students.enrollment_number, students.name, logs.timestamp, logs.status 
                        FROM logs 
                        JOIN students ON logs.student_id = students.student_id 
                        ORDER BY logs.timestamp DESC''')
        data = cursor.fetchall()

        # Setup Table
        logs_table.setRowCount(len(data))
        logs_table.setColumnCount(4)
        logs_table.setHorizontalHeaderLabels(["Enrollment", "Name", "Timestamp", "Status"])

        for row, items in enumerate(data):
            for col, item in enumerate(items):
                logs_table.setItem(row, col, QTableWidgetItem(str(item)))

        logs_table.setEditTriggers(QTableWidget.NoEditTriggers)  # Make it read-only

        dialog.setLayout(layout)
        dialog.exec_()


    def setup_admin_menu(self):
        menu = self.menuBar()
        admin_menu = menu.addMenu("Admin")
        
        add_student = QAction("Add Student", self)
        add_student.triggered.connect(self.show_add_student_dialog)
        admin_menu.addAction(add_student)
        
        backup_action = QAction("Create Backup", self)
        backup_action.triggered.connect(self.create_backup)
        admin_menu.addAction(backup_action)

    def show_add_student_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Add Student")
        dialog.setModal(True)

        layout = QVBoxLayout()

        # Info label
        format_label = QLabel(
            "Required Format (CSV/Excel):\n"
            "Columns: Name, Enrollment Number, Department, Year\n"
            "Example:\nJohn Doe, ENR001, CS, 3"
        )
        layout.addWidget(format_label)

        # Manual form fields
        name_input = QLineEdit()
        enrollment_input = QLineEdit()
        department_input = QLineEdit()
        year_input = QSpinBox()
        year_input.setMinimum(1)
        year_input.setMaximum(6)

        # Buttons
        add_button = QPushButton("Add Student")
        upload_button = QPushButton("Upload CSV/Excel")
        cancel_button = QPushButton("Cancel")

        # Layout setup
        layout.addWidget(QLabel("Name:"))
        layout.addWidget(name_input)
        layout.addWidget(QLabel("Enrollment Number:"))
        layout.addWidget(enrollment_input)
        layout.addWidget(QLabel("Department:"))
        layout.addWidget(department_input)
        layout.addWidget(QLabel("Year:"))
        layout.addWidget(year_input)
        layout.addWidget(add_button)
        layout.addWidget(upload_button)
        layout.addWidget(cancel_button)

        dialog.setLayout(layout)

        # Function to insert single student
        def add_student():
            name = name_input.text().strip()
            enrollment = enrollment_input.text().strip()
            department = department_input.text().strip()
            year = year_input.value()

            if not name or not enrollment:
                QMessageBox.warning(dialog, "Error", "Name and Enrollment Number are required!")
                return

            try:
                cursor.execute("INSERT INTO students (name, enrollment_number, department, year) VALUES (?, ?, ?, ?)",
                            (name, enrollment, department, year))
                conn.commit()
                QMessageBox.information(dialog, "Success", "Student added successfully!")
                dialog.accept()
            except sqlite3.IntegrityError:
                QMessageBox.warning(dialog, "Error", "Enrollment number already exists!")

        # Function to upload and validate CSV/Excel file
        def upload_file():
            file_path, _ = QFileDialog.getOpenFileName(dialog, "Select File", "", "CSV Files (*.csv);;Excel Files (*.xlsx)")

            if not file_path:
                return

            # Read file based on extension
            if file_path.endswith('.csv'):
                df = pd.read_csv(file_path)
            elif file_path.endswith('.xlsx'):
                df = pd.read_excel(file_path)
            else:
                QMessageBox.warning(dialog, "Error", "Invalid file format. Please upload a CSV or Excel file.")
                return

            # Required columns
            required_columns = {"Name", "Enrollment Number", "Department", "Year"}

            # Check if all required columns exist
            if not required_columns.issubset(set(df.columns)):
                QMessageBox.warning(dialog, "Error", "Missing required columns in the file! \nExpected: Name, Enrollment Number, Department, Year")
                return

            # Validate data
            warnings = []
            for index, row in df.iterrows():
                name = str(row["Name"]).strip()
                enrollment = str(row["Enrollment Number"]).strip()
                department = str(row["Department"]).strip()
                year = row["Year"]

                # Check missing values
                if not name or not enrollment:
                    warnings.append(f"Row {index + 1}: Name or Enrollment Number is missing.")

                # Check year validity
                if not (1 <= int(year) <= 6):
                    warnings.append(f"Row {index + 1}: Year {year} is invalid.")

            # Show warnings if any
            if warnings:
                QMessageBox.warning(dialog, "Data Issues", "\n".join(warnings))
                return

            # Insert into database
            for _, row in df.iterrows():
                try:
                    cursor.execute("INSERT INTO students (name, enrollment_number, department, year) VALUES (?, ?, ?, ?)",
                                (row["Name"], row["Enrollment Number"], row["Department"], row["Year"]))
                except sqlite3.IntegrityError:
                    warnings.append(f"Enrollment Number {row['Enrollment Number']} already exists.")

            conn.commit()
            QMessageBox.information(dialog, "Success", "Students added successfully!")

        # Connect buttons
        add_button.clicked.connect(add_student)
        upload_button.clicked.connect(upload_file)
        cancel_button.clicked.connect(dialog.reject)

        dialog.exec_()


    def create_backup(self):
        backup_dir = "backups"
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
        shutil.copy('student_tracking.db', f'{backup_dir}/backup_{QDateTime.currentDateTime().toString("yyyyMMdd_hhmmss")}.db')
        QMessageBox.information(self, "Success", "Database backup created")

    def log_entry_exit(self):
        enrollment = self.enrollment_input.text()
        cursor.execute("SELECT student_id FROM students WHERE enrollment_number=?", (enrollment,))
        result = cursor.fetchone()
        
        if result:
            student_id = result[0]
            last_status = self.get_last_status(student_id)
            new_status = 'exit' if last_status == 'entry' else 'entry'
            
            timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
            cursor.execute("INSERT INTO logs (student_id, timestamp, status) VALUES (?,?,?)",
                          (student_id, timestamp, new_status))
            conn.commit()
            
            self.update_status_count()
            self.enrollment_input.clear()
        else:
            QMessageBox.warning(self, "Error", "Invalid enrollment number")

    def get_last_status(self, student_id):
        cursor.execute("SELECT status FROM logs WHERE student_id=? ORDER BY timestamp DESC LIMIT 1", (student_id,))
        result = cursor.fetchone()
        return result[0] if result else 'exit'

    def update_status_count(self):
        cursor.execute('''SELECT COUNT(DISTINCT student_id) FROM logs 
                       WHERE (student_id, timestamp) IN 
                       (SELECT student_id, MAX(timestamp) FROM logs GROUP BY student_id) 
                       AND status='entry' ''')
        count = cursor.fetchone()[0]
        self.status_label.setText(f"Students Inside: {count}")

    def setup_logs_tab(self):
        self.logs_table = QTableWidget()
        self.tabs.addTab(self.logs_table, "Logs")
        self.update_logs_table()

    def update_logs_table(self):
        cursor.execute('''SELECT students.enrollment_number, logs.timestamp, logs.status 
                       FROM logs JOIN students ON logs.student_id = students.student_id''')
        data = cursor.fetchall()
        
        self.logs_table.setRowCount(len(data))
        self.logs_table.setColumnCount(3)
        self.logs_table.setHorizontalHeaderLabels(["Enrollment", "Timestamp", "Status"])
        
        for row, items in enumerate(data):
            for col, item in enumerate(items):
                self.logs_table.setItem(row, col, QTableWidgetItem(str(item)))

    def setup_analytics_tab(self):
        analytics_tab = QWidget()
        layout = QVBoxLayout()
        
        # Matplotlib Figure
        self.figure = plt.figure()
        self.canvas = FigureCanvas(self.figure)
        layout.addWidget(self.canvas)
        
        # Date selection
        date_layout = QHBoxLayout()
        self.start_date = QDateEdit()
        self.end_date = QDateEdit()
        date_layout.addWidget(QLabel("From:"))
        date_layout.addWidget(self.start_date)
        date_layout.addWidget(QLabel("To:"))
        date_layout.addWidget(self.end_date)
        layout.addLayout(date_layout)
        
        analytics_tab.setLayout(layout)
        self.tabs.addTab(analytics_tab, "Analytics")
        self.start_date.dateChanged.connect(self.update_chart)
        self.end_date.dateChanged.connect(self.update_chart)

    def update_chart(self):
        self.figure.clear()
        ax = self.figure.add_subplot(111)
        
        # Sample data visualization
        cursor.execute('''SELECT strftime('%H', timestamp), COUNT(*) 
                       FROM logs GROUP BY strftime('%H', timestamp)''')
        hours = []
        counts = []
        for row in cursor.fetchall():
            hours.append(row[0])
            counts.append(row[1])
        
        ax.bar(hours, counts)
        ax.set_xlabel("Hour of Day")
        ax.set_ylabel("Number of Entries/Exits")
        self.canvas.draw()

    def update_clock(self):
        self.clock_label.setText(QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss"))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    login = LoginWindow()
    login.show()
    sys.exit(app.exec_())