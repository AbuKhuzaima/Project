# models.py

from app import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import uuid # Import the uuid module

class Student(UserMixin, db.Model):
    __tablename__ = 'students'

    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"

    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(150), nullable=False)
    last_name = db.Column(db.String(150), nullable=False)
    registration_number = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    # Password Reset Fields
    reset_token = db.Column(db.String(256), nullable=True)
    reset_token_expiration = db.Column(db.DateTime, nullable=True)


    # Profile
    level = db.Column(db.String(50))
    faculty = db.Column(db.String(100))
    department = db.Column(db.String(100))
    phone_number = db.Column(db.String(20))
    profile_picture = db.Column(db.String(100), default='default.jpg')
    hostel = db.Column(db.String(20))       # 'ICSA' or 'Ramat'
    block = db.Column(db.String(5))         # 'A' to 'N' etc.
    room_number = db.Column(db.Integer)     # room number as per continuous numbering

    # NEW FIELD FOR QR CODE ID
    clearance_qr_id = db.Column(db.String(36), unique=True, nullable=True) # UUIDs are 36 chars long


    # Relationship: One student -> many documents
    documents = db.relationship('Document', backref='student', lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # NEW METHOD TO GENERATE QR ID
    def generate_clearance_qr_code_id(self):
        if not self.clearance_qr_id: # Only generate if one doesn't exist
            self.clearance_qr_id = str(uuid.uuid4()) # Generate a UUID
            db.session.add(self)
            db.session.commit()
        return self.clearance_qr_id

    # NEW METHODS FOR PASSWORD RESET
    def get_password_hash(self, token):
        # Using the same hashing method as for the password
        return generate_password_hash(token)

    def check_password_hash(self, hashed_token, token):
        return check_password_hash(hashed_token, token)


class Document(db.Model):
    __tablename__ = 'documents'

    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id'), nullable=False)

    # One of: school_fee, accommodation, id_or_admission, passport
    doc_type = db.Column(db.String(64), nullable=False)

    filename = db.Column(db.String(128), nullable=False)
    verified = db.Column(db.Boolean, default=False)
    rejection_reason = db.Column(db.String(256), nullable=True)
    uploaded_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Clearance(db.Model):
    __tablename__ = 'clearances'

    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id'), nullable=False)
    clearance_type = db.Column(db.String(64), nullable=False)
    status = db.Column(db.String(50), nullable=False, default='not uploaded')
    verified = db.Column(db.Boolean, default=False)
    cleared_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    student = db.relationship('Student', backref='clearances')

class Notification(db.Model):
    __tablename__ = 'notifications'

    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id'), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    student = db.relationship('Student', backref='notifications')

class ActivityLog(db.Model):
    __tablename__ = 'activity_logs'

    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'), nullable=True)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id'), nullable=True)

    action = db.Column(db.String(200), nullable=False)  # e.g., "Verified document", "Cleared student"
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    admin = db.relationship('Admin', backref='activity_logs')
    student = db.relationship('Student', backref='activity_logs')