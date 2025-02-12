**Student Tracking System**

### Overview
The Student Tracking System is a desktop application built using Python and PyQt5 for tracking student entries and exits. It utilizes an SQLite database to store student records, login credentials, and log entries. The system includes user authentication, a logging mechanism for tracking students, data visualization through Matplotlib, and administrative functionalities like adding students and creating database backups.

---

### Features
- **User Authentication:** Secure login with password hashing (bcrypt) and role-based access (admin/security).
- **Student Entry/Exit Tracking:** Log students' entry and exit times based on their enrollment number.
- **Live Status Update:** Displays the number of students currently inside.
- **Admin Panel:**
  - Add students manually or via CSV/Excel upload.
  - Create database backups.
- **Security Panel:**
  - View logs of student movements.
  - Read-only access to logs.
- **Data Visualization:** Graphs of student activity trends using Matplotlib.
- **Real-time Clock:** Displays the current date and time.

---

### Installation & Setup
#### Prerequisites:
- Python 3.x
- Required libraries:
  ```sh
  pip install pyqt5 bcrypt matplotlib pandas
  ```

#### Running the Application:
1. Clone or download the project.
2. Navigate to the project folder and run:
   ```sh
   python app.py
   ```
3. The login window will appear. Default credentials (if applicable) should be used initially.

#### Default Database Tables:
Upon first launch, the system initializes three tables:
- **Students**: Stores student details.
- **Logs**: Tracks student entry/exit records.
- **Users**: Manages authentication.

---

### Usage Guide
#### **Login**
- Enter username and password.
- Admins can manage students and logs.
- Security personnel can only view logs.

#### **Tracking Entries/Exits**
- Enter the student’s enrollment number.
- Click **Submit** to log the entry/exit.

#### **Admin Functionalities**
- **Add Students:** Manually or via CSV/Excel.
- **Create Backup:** Saves a copy of the database.

#### **Viewing Logs**
- Security personnel can view logs in read-only mode.
- Admins have full access to data.

#### **Analytics Dashboard**
- View student movement trends over time.


