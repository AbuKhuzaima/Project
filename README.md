# Hostel Clearance System

## Description
The Hostel Clearance System is a Flask-based web application designed to streamline and automate the process of student hostel clearance. This system facilitates student registration, allows for the upload and management of necessary documents (such as school fees, accommodation proof, ID, and passport), and provides administrators with tools to verify these documents. Upon successful verification, the system generates unique QR codes for student clearance. Additionally, it incorporates logic for managing hostel and room allocations within different hostel facilities.

## Features
*   **Student Authentication:** Secure registration and login for students.
*   **Admin Authentication:** Separate login for administrators to manage the clearance process.
*   **Profile Management:** Students can manage their personal details including academic level, faculty, department, contact information, and hostel allocation details (hostel, block, room number).
*   **Document Management:**
    *   Students can upload various types of documents (e.g., school fees, accommodation receipts, identification, passport photos).
    *   Administrators can review, verify, and reject uploaded documents, providing reasons for rejection.
*   **Clearance Tracking:** Students and administrators can track the real-time status of clearance applications.
*   **QR Code Generation:** Automatic generation of unique QR codes for verified student clearances.
*   **Hostel and Room Allocation:** Integrated logic for managing hostel blocks and room capacities for different hostels (e.g., ICSA, Ramat).
*   **Password Reset:** Functionality for users to reset forgotten passwords.
*   **Activity Logging & Notifications:** System logs and notifications for important actions and updates.

## Technologies Used
*   **Backend:** Python 3, Flask
*   **Database:** SQLite (SQLAlchemy ORM, Flask-SQLAlchemy)
*   **Authentication:** Flask-Login
*   **Database Migrations:** Flask-Migrate
*   **Web Server Gateway Interface (WSGI):** Werkzeug
*   **Templating:** Jinja2
*   **Security:** Werkzeug Security (for password hashing)
*   **QR Code Generation:** `qrcode` library
*   **Other Python Libraries:** `blinker`, `click`, `colorama`, `itsdangerous`, `MarkupSafe`, `typing_extensions`

## Installation

### Prerequisites
*   Python 3.8+
*   `pip` (Python package installer)

### Steps

1.  **Clone the repository:**
    ```bash
    git clone <repository_url>
    cd Hostel\ Clearance
    ```
    (Replace `<repository_url>` with the actual URL of your repository.)

2.  **Create a Virtual Environment:**
    It's recommended to use a virtual environment to manage dependencies.
    ```bash
    python -m venv venv
    ```

3.  **Activate the Virtual Environment:**
    *   **On Windows:**
        ```bash
        .\venv\Scripts\activate
        ```
    *   **On macOS/Linux:**
        ```bash
        source venv/bin/activate
        ```

4.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

5.  **Initialize the Database:**
    The application will create the database automatically upon first run or by explicitly running `create_db.py`.
    ```bash
    python create_db.py
    ```
    This will create an `instance/` directory and `hostel.db` within it.

## Usage

1.  **Run the Application:**
    Ensure your virtual environment is activated, then run:
    ```bash
    python run.py
    ```
    The application will typically run on `http://127.0.0.1:5000/` (or `localhost:5000`).

2.  **Access the Application:**
    Open your web browser and navigate to the address provided in your terminal (e.g., `http://127.0.0.1:5000/`).

## Database Setup (Development)

The application uses SQLite, and the database file `hostel.db` is created in the `instance/` directory when `create_db.py` or `run.py` is executed for the first time.

**Note on Migrations:** This project uses `Flask-Migrate`. While `db.create_all()` is called on app startup for convenience, for production environments and schema evolution, you would typically use Flask-Migrate commands:
```bash
flask db init
flask db migrate -m "Initial migration"
flask db upgrade
```

## Contributing
If you'd like to contribute, please follow these steps:
1.  Fork the repository.
2.  Create a new branch for your feature or bug fix.
3.  Make your changes and ensure they adhere to the project's coding standards.
4.  Write appropriate tests for your changes.
5.  Submit a pull request with a clear description of your changes.

## License
[Specify your license here, e.g., MIT License, Apache 2.0 License, etc.]

## Security Considerations
*   **`SECRET_KEY`:** The `SECRET_KEY` is currently hardcoded in `app/__init__.py`. **For production deployments, it is CRITICAL to change this to a strong, randomly generated value and manage it securely using environment variables.** For example:
    ```python
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'a_very_secret_key_that_is_not_hardcoded_in_production'
    ```
*   **Input Validation:** Ensure all user inputs are thoroughly validated on the server-side to prevent common web vulnerabilities like SQL injection and XSS.
*   **Password Storage:** Passwords are hashed using `werkzeug.security`, which is good practice.
*   **File Uploads:** Implement robust file upload security, including checking file types, sizes, and scanning for malicious content, especially if the uploaded files are publicly accessible. The current implementation uses `secure_filename`, which is a good start.

---
