import os
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from app import db # Assuming 'app' is your Flask application instance
from app.models import Student, Document, Admin, Clearance, Notification, ActivityLog # Import all your models
from flask_login import login_user, logout_user, login_required, current_user
from sqlalchemy import func, desc, case
from flask import current_app
from werkzeug.utils import secure_filename
from functools import wraps
from collections import defaultdict
import secrets
from datetime import datetime, timedelta
import qrcode
import qrcode.image.svg
from io import BytesIO
import base64
from sqlalchemy import desc
import random


main = Blueprint('main', __name__)

# --- CENTRALIZED HOSTEL & ROOM DETAILS FOR ALLOCATION LOGIC ---
HOSTEL_BLOCKS = {
    "ICSA": list("ABCDEFGHIJKLMN"),
    "Ramat": list("ABCDE")
}

ICSA_ROOM_DETAILS = {
    "A": {'rooms':20, 'capacity':4}, "B": {'rooms':20, 'capacity':4}, "C": {'rooms':20, 'capacity':4}, "D": {'rooms':20, 'capacity':4}, "E": {'rooms':20, 'capacity':4},
    "F": {'rooms':20, 'capacity':6}, "G": {'rooms':24, 'capacity':6}, "H": {'rooms':24, 'capacity':6}, "I": {'rooms':24, 'capacity':6}, "J": {'rooms':24, 'capacity':6},
    "K": {'rooms':24, 'capacity':6}, "L": {'rooms':24, 'capacity':6}, "M": {'rooms':24, 'capacity':6}, "N": {'rooms':20, 'capacity':6},
}

RAMAT_ROOM_DETAILS = {
    "A": {'rooms':20, 'capacity':4}, "B": {'rooms':20, 'capacity':4}, "C": {'rooms':20, 'capacity':4}, "D": {'rooms':20, 'capacity':4}, "E": {'rooms':20, 'capacity':4},
}

def get_block_room_start(hostel, block):
    """Calculates the starting global room number for a given block."""
    room_details = ICSA_ROOM_DETAILS if hostel == "ICSA" else RAMAT_ROOM_DETAILS
    blocks_in_hostel = HOSTEL_BLOCKS[hostel]
    start = 1
    for blk in blocks_in_hostel:
        if blk == block:
            break
        start += room_details[blk]['rooms']
    return start

def get_room_details_for_hostel(hostel, block):
    """Returns room details (num_rooms, capacity) for a specific block in a hostel."""
    if hostel == "ICSA":
        return ICSA_ROOM_DETAILS.get(block)
    elif hostel == "Ramat":
        return RAMAT_ROOM_DETAILS.get(block)
    return None

# --- END CENTRALIZED HOSTEL & ROOM DETAILS ---


##########Registration###############


@main.route('/student_registration', methods=['GET', 'POST'])
def student_registration():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        registration_number = request.form.get('registration_number')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Simple validations
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('main.student_registration'))

        # Check if email or registration number already exist
        if Student.query.filter_by(email=email).first():
            flash('Email already registered!', 'danger')
            return redirect(url_for('main.student_registration'))

        if Student.query.filter_by(registration_number=registration_number).first():
            flash('Registration number already registered!', 'danger')
            return redirect(url_for('main.student_registration'))

        # Create new student and hash password
        new_student = Student(
            first_name=first_name,
            last_name=last_name,
            registration_number=registration_number,
            email=email
        )
        new_student.set_password(password)

        db.session.add(new_student)
        db.session.commit()

        # Log student registration activity
        new_activity = ActivityLog(student_id=new_student.id, action=f"Student '{new_student.full_name}' registered.")
        db.session.add(new_activity)
        db.session.commit()

        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('main.student_login'))

    return render_template('student_registration.html')

########## Login #############


@main.route('/', methods=['GET', 'POST'])
def student_login():
    if current_user.is_authenticated:
        # Check if the user is an admin (if Flask-Login manages both roles)
        # If admin, redirect to admin dashboard, else to student dashboard
        try:
            if hasattr(current_user, 'is_admin') and current_user.is_admin:
                return redirect(url_for('main.admin_dashboard'))
        except AttributeError:
            pass # Not an admin, proceed to student dashboard
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        registration_number = request.form.get('registration_number')
        password = request.form.get('password')

        # UPDATED: Use func.lower() for case-insensitive login
        student = Student.query.filter(func.lower(Student.registration_number) == func.lower(registration_number)).first()

        if student and student.check_password(password):
            login_user(student)
            # Log student login activity
            new_activity = ActivityLog(student_id=student.id, action=f"Student '{student.full_name}' logged in.")
            db.session.add(new_activity)
            db.session.commit()
            flash('Logged in successfully, please update yout profile; ignore this message if your information is already up to date.', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            flash('Invalid registration number or password', 'danger')

    return render_template('student_login.html')


######### Logout #############


@main.route('/logout')
@login_required
def logout():
    # Log student logout activity
    if current_user.is_authenticated and hasattr(current_user, 'full_name'): # Ensure it's a student and not an admin trying to use student logout
        new_activity = ActivityLog(student_id=current_user.id, action=f"Student '{current_user.full_name}' logged out.")
        db.session.add(new_activity)
        db.session.commit()

    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.student_login'))


# --- START NEW PASSWORD RESET ROUTES ---

@main.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        student = Student.query.filter_by(email=email).first()

        # Prevent user enumeration by giving a generic success message
        if student:
            # Generate a secure, temporary token
            token = secrets.token_urlsafe(32)
            # Make sure this method is implemented in your Student model
            hashed_token = student.get_password_hash(token) 
            
            student.reset_token = hashed_token
            student.reset_token_expiration = datetime.utcnow() + timedelta(hours=1)
            db.session.commit()

            # --- Placeholder for sending the email ---
            # You would need to configure Flask-Mail or a similar service
            reset_url = url_for('main.reset_password', token=token, _external=True)
            # msg = Message('Password Reset Request', sender='your-email@example.com', recipients=[student.email])
            # msg.body = f'To reset your password, visit the following link: {reset_url}'
            # mail.send(msg)
            print(f"Password reset link for {student.email}: {reset_url}")
            # --- End email placeholder ---

        flash('If an account with that email exists, you will receive a password reset link.', 'info')
        return redirect(url_for('main.student_login'))
    
    return render_template('forgot_password.html')

@main.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # Find the user by the hashed token and check for expiration
    student = Student.query.filter(Student.reset_token_expiration > datetime.utcnow()).first()

    # The original logic here was incorrect, it was trying to check against a hashed token
    # while the token passed was a plain text one. The correct approach is to iterate
    # through all users with valid tokens and check against the token passed.
    valid_student = None
    if student:
        # Check if the token passed matches the stored hashed token for the found student
        if student.check_password_hash(student.reset_token, token):
            valid_student = student
    
    if valid_student is None:
        flash('That is an invalid or expired token. Please try again.', 'danger')
        return redirect(url_for('main.forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('main.reset_password', token=token))
        
        valid_student.set_password(password)
        valid_student.reset_token = None
        valid_student.reset_token_expiration = None
        db.session.commit()

        flash('Your password has been reset! You can now log in with your new password.', 'success')
        return redirect(url_for('main.student_login'))
    
    return render_template('reset_password.html', token=token)

# --- END NEW PASSWORD RESET ROUTES ---


######## student dashboard ##########

@main.route('/dashboard')
@login_required
def dashboard():
    user_documents = Document.query.filter_by(student_id=current_user.id).all()

    required_docs = ['school_fee', 'accommodation', 'id_or_admission', 'passport']

    doc_statuses = []
    approved_documents_count = 0

    for doc_type in required_docs:
        doc = next((d for d in user_documents if d.doc_type == doc_type), None)

        if doc:
            if doc.verified:
                status = 'verified'
                reason = ''
                approved_documents_count += 1
            else:
                status = 'failed' if doc.rejection_reason else 'pending'
                reason = doc.rejection_reason or ''
        else:
            # UPDATED: Set the status to 'not_uploaded' if no document exists
            status = 'not_uploaded'
            reason = ''

        doc_statuses.append({
            'doc_type': doc_type.replace('_', ' ').title(),
            'status': status,
            'reason': reason
        })

    total_required_documents = len(required_docs)

    if total_required_documents > 0:
        approval_percentage = (approved_documents_count / total_required_documents) * 100
    else:
        approval_percentage = 0

    student_notifications = Notification.query.filter_by(student_id=current_user.id, is_read=False).order_by(Notification.created_at.desc()).all()

    # --- START QR CODE GENERATION LOGIC ---
    # Ensure the student has a QR ID, generate if not
    if not current_user.clearance_qr_id:
        current_user.generate_clearance_qr_code_id() # This method already handles db.session.add/commit
        # No need for db.session.commit() here as generate_clearance_qr_code_id does it
        # You might want to reload the student object or ensure changes are reflected if not in session
        # For simplicity, relying on the method to commit
    db.session.refresh(current_user) # Refresh to ensure the latest clearance_qr_id is loaded

    verification_url = url_for('main.verify_clearance', qr_id=current_user.clearance_qr_id, _external=True)

    qr_img_data = BytesIO()
    img = qrcode.make(verification_url, image_factory=qrcode.image.svg.SvgImage)
    img.save(qr_img_data)
    qr_img_data.seek(0)
    qr_base64 = base64.b64encode(qr_img_data.getvalue()).decode('utf-8')
    # --- END QR CODE GENERATION LOGIC ---

    # --- NEW: Check if student has allocated room ---
    has_allocated_room = current_user.hostel is not None and current_user.block is not None and current_user.room_number is not None

    return render_template('student_dashboard.html',
                           documents=user_documents,
                           doc_statuses=doc_statuses,
                           student_notifications=student_notifications,
                           approved_documents_count=approved_documents_count,
                           total_required_documents=total_required_documents,
                           approval_percentage=approval_percentage,
                           qr_code_svg_data=qr_base64,
                           has_allocated_room=has_allocated_room) # Pass this to the template


@main.route('/student_profile')
@login_required
def student_profile():
    student_notifications = Notification.query.filter_by(student_id=current_user.id, is_read=False).order_by(Notification.created_at.desc()).all()
    return render_template('student_profile.html', student_notifications=student_notifications)


@main.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    student_notifications = Notification.query.filter_by(student_id=current_user.id, is_read=False).order_by(Notification.created_at.desc()).all()
    if request.method == 'POST':
        current_user.level = request.form.get('level')
        current_user.faculty = request.form.get('faculty')
        current_user.department = request.form.get('department')
        current_user.phone_number = request.form.get('phone_number')

        current_user.first_name = request.form.get('first_name')
        current_user.last_name = request.form.get('last_name')
        current_user.email = request.form.get('email')

        picture = request.files.get('profile_picture')
        if picture and picture.filename != '':
            filename = secure_filename(picture.filename)
            picture_path = os.path.join(current_app.root_path, 'static/profile_pics', filename)
            picture.save(picture_path)
            current_user.profile_picture = filename

        db.session.commit()
        # Log profile update activity
        new_activity = ActivityLog(student_id=current_user.id, action=f"Student '{current_user.full_name}' updated their profile.")
        db.session.add(new_activity)
        db.session.commit()
        flash('Profile updated successfully', 'success')
        return redirect(url_for('main.dashboard'))

    return render_template('edit_profile.html', student_notifications=student_notifications)


# --- NEW: Automatic Room Allocation Route ---
@main.route('/allocate_room', methods=['POST'])
@login_required
def allocate_room():
    if current_user.hostel and current_user.block and current_user.room_number:
        return jsonify({'success': False, 'message': 'You have already been allocated a room.',
                        'hostel': current_user.hostel, 'block': current_user.block, 'room_number': current_user.room_number}), 400

    allocated = False
    max_attempts = 100 # Prevent infinite loops in case all rooms are genuinely full or logic error
    attempt = 0

    while not allocated and attempt < max_attempts:
        attempt += 1

        # 1. Randomly select a hostel
        hostel = random.choice(list(HOSTEL_BLOCKS.keys()))

        # 2. Randomly select a block within that hostel
        blocks_for_hostel = HOSTEL_BLOCKS[hostel]
        block = random.choice(blocks_for_hostel)

        # 3. Get room details for the selected block
        room_details = get_room_details_for_hostel(hostel, block)
        if not room_details: # Should not happen with correct data, but safety check
            continue

        num_rooms_in_block = room_details['rooms']
        max_capacity_per_room = room_details['capacity']

        # 4. Calculate global room number range for the block
        start_room = get_block_room_start(hostel, block)
        end_room = start_room + num_rooms_in_block - 1

        # 5. Randomly select a room number within the block's range
        room_number = random.randint(start_room, end_room)

        # 6. Check existing occupants for the chosen room
        existing_occupants = Student.query.filter_by(
            hostel=hostel,
            block=block,
            room_number=room_number
        ).count()

        if existing_occupants < max_capacity_per_room:
            # Room is available, assign it
            current_user.hostel = hostel
            current_user.block = block
            current_user.room_number = room_number
            db.session.commit()
            allocated = True

            # Log activity
            new_activity = ActivityLog(student_id=current_user.id,
                                       action=f"Student '{current_user.full_name}' was automatically allocated {hostel} Block {block} Room {room_number}.")
            db.session.add(new_activity)

            # Send notification
            notification_message = f"Congratulations! You have been automatically allocated a room: Hostel {hostel}, Block {block}, Room {room_number}."
            new_notification = Notification(student_id=current_user.id, message=notification_message)
            db.session.add(new_notification)
            db.session.commit()

            return jsonify({'success': True, 'message': 'Room allocated successfully!',
                            'hostel': hostel, 'block': block, 'room_number': room_number})

    # If allocation failed after max_attempts
    return jsonify({'success': False, 'message': 'Could not allocate a room at this time. Please try again later or contact support.'}), 500


# --- MODIFIED: hostel_info route to be display-only ---
@main.route('/hostel_info', methods=['GET']) # Removed POST method
@login_required
def hostel_info():
    student_notifications = Notification.query.filter_by(student_id=current_user.id, is_read=False).order_by(Notification.created_at.desc()).all()
    # This page now only displays allocated info or a message
    if current_user.hostel and current_user.block and current_user.room_number:
        return render_template('hostel_info.html',
                               hostel=current_user.hostel,
                               block=current_user.block,
                               room_number=current_user.room_number,
                               allocated=True,
                               student_notifications=student_notifications)
    else:
        # If no room allocated, inform the student and redirect to dashboard
        flash("Your room has not been allocated yet. Please click 'Allocate Room' on your dashboard.", "info")
        return redirect(url_for('main.dashboard'))


# MODIFIED route to handle AJAX requests and return JSON
@main.route('/upload_document/<doc_type>', methods=['POST'])
@login_required
def upload_document(doc_type):
    allowed_types = ['school_fee', 'accommodation', 'id_or_admission', 'passport']
    if doc_type not in allowed_types:
        return jsonify({'message': 'Invalid document type.'}), 400

    file = request.files.get('file')
    if file and file.filename:
        filename = secure_filename(file.filename)
        save_path = os.path.join(current_app.root_path, 'static', 'uploads', filename)
        file.save(save_path)

        # Check if document already uploaded, then update it
        existing_doc = Document.query.filter_by(student_id=current_user.id, doc_type=doc_type).first()
        if existing_doc:
            old_filename = existing_doc.filename
            existing_doc.filename = filename
            existing_doc.verified = False  # re-verify if reuploaded
            existing_doc.rejection_reason = None # Clear any previous rejection reason
            existing_doc.uploaded_at = datetime.utcnow() # Update timestamp on re-upload
            activity_action = f"Student '{current_user.full_name}' re-uploaded '{doc_type.replace('_', ' ').title()}'."
            # Optionally delete old file
            # old_file_path = os.path.join(current_app.root_path, 'static', 'uploads', old_filename)
            # if os.path.exists(old_file_path):
            #     os.remove(old_file_path)
        else:
            new_doc = Document(student_id=current_user.id, doc_type=doc_type, filename=filename)
            db.session.add(new_doc)
            activity_action = f"Student '{current_user.full_name}' uploaded '{doc_type.replace('_', ' ').title()}'."


        # Get or create a Clearance record for the student
        clearance = Clearance.query.filter_by(student_id=current_user.id).first()
        if not clearance:
            clearance = Clearance(student_id=current_user.id, clearance_type='Initial Upload', status='pending', verified=False)
            db.session.add(clearance)
        elif clearance.status != 'pending' or clearance.verified: # If it was approved/rejected, set back to pending on re-upload
            clearance.status = 'pending'
            clearance.verified = False
            clearance.cleared_at = None

        db.session.commit()
        # Log document upload activity
        new_activity = ActivityLog(student_id=current_user.id, action=activity_action)
        db.session.add(new_activity)
        db.session.commit()

        # Return a JSON response for the AJAX call
        return jsonify({'message': f'Document uploaded successfully. It is now pending review.'}), 200
    else:
        # Return a JSON response for the AJAX call
        return jsonify({'message': 'Please select a file.'}), 400





# --- NEW ROUTE FOR MARKING NOTIFICATIONS AS READ ---
@main.route('/mark_notification_read/<int:notification_id>', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    """Marks a single notification as read in the database."""
    try:
        # Crucial security check: Ensure the notification belongs to the current student
        notification = Notification.query.filter_by(
            id=notification_id,
            student_id=current_user.id
        ).first()

        if notification:
            # Update the is_read status
            notification.is_read = True
            db.session.commit()
            
            # Return a success message to the front end
            return jsonify({'success': True}), 200
        else:
            # Notification not found or doesn't belong to the user
            return jsonify({'success': False, 'error': 'Notification not found or access denied.'}), 404
    except Exception as e:
        # Handle any potential errors during the database operation
        print(f"Error marking notification as read: {e}")
        db.session.rollback() # Rollback the session in case of error
        return jsonify({'success': False, 'error': 'An error occurred.'}), 500

# --- START NEW: VERIFICATION ENDPOINT FOR ADMIN/STAFF ---
@main.route('/verify-clearance/<qr_id>')
def verify_clearance(qr_id):
    # 1. Find the student associated with this QR ID
    student = Student.query.filter_by(clearance_qr_id=qr_id).first()

    if not student:
        flash('Invalid QR Code. Clearance cannot be verified.', 'error')
        return render_template('verification_result.html', status='invalid')

    # 2. Calculate the student's current clearance status based on documents
    user_documents = Document.query.filter_by(student_id=student.id).all()
    required_docs = ['school_fee', 'accommodation', 'id_or_admission', 'passport']
    approved_documents_count = 0
    doc_details_for_display = []

    for doc_type in required_docs:
        doc = next((d for d in user_documents if d.doc_type == doc_type), None)
        status_detail = {
            'doc_type': doc_type.replace('_', ' ').title(),
            'status': 'pending',
            'reason': ''
        }
        if doc:
            status_detail['status'] = 'verified' if doc.verified else ('rejected' if doc.rejection_reason else 'pending')
            status_detail['reason'] = doc.rejection_reason or ''
            if doc.verified:
                approved_documents_count += 1
        doc_details_for_display.append(status_detail)

    total_required_documents = len(required_docs)
    overall_clearance_status = "Approved" if approved_documents_count == total_required_documents else "Pending"

    # 3. Render the verification result template
    return render_template('verification_result.html',
                           status='valid',
                           student=student,
                           overall_clearance_status=overall_clearance_status,
                           doc_details=doc_details_for_display,
                           approved_count=approved_documents_count,
                           total_count=total_required_documents)
# --- END NEW: VERIFICATION ENDPOINT ---

################### ADMIN ###################


@main.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    # If a student is logged in, log them out first if they try to access admin login
    if current_user.is_authenticated:
        logout_user() # Log out any currently authenticated student
        flash('You have been logged out from student account to access admin login.', 'info')

    if 'admin_id' in session: # If an admin is already logged in via session
        return redirect(url_for('main.admin_dashboard'))


    if request.method == 'POST':
        username = request.form['admin_username']
        password = request.form['admin_password']
        admin = Admin.query.filter_by(username=username).first()
        if admin and admin.check_password(password):
            session['admin_id'] = admin.id
            # Log admin login activity
            new_activity = ActivityLog(admin_id=admin.id, action=f"Admin '{admin.username}' logged in.")
            db.session.add(new_activity)
            db.session.commit()
            return redirect(url_for('main.admin_dashboard'))
        flash('Invalid username or password', 'danger')
    return render_template('admin_login.html')


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            flash('Admin login required.', 'warning')
            return redirect(url_for('main.admin_login'))
        # Optional: Re-fetch admin from DB to ensure session is valid and user exists
        admin = Admin.query.get(session['admin_id'])
        if not admin:
            session.pop('admin_id', None) # Clear invalid session
            flash('Admin session invalid. Please log in again.', 'warning')
            return redirect(url_for('main.admin_login'))
        # For admin, we don't use current_user from Flask-Login usually, stick to session['admin_id']
        return f(*args, **kwargs)
    return decorated_function


@main.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    total_students = Student.query.count()

    # Define required document types for a full clearance
    required_doc_types = ['school_fee', 'accommodation', 'id_or_admission', 'passport']
    num_required_docs = len(required_doc_types)

    # --- START FIX: Optimized Clearance Status Counts ---
    # Optimized query to get all counts in a single database roundtrip
    # This is much more efficient than the original loop
    subquery = db.session.query(
        Document.student_id,
        func.count(case((Document.verified.is_(True), 1))).label('approved_count'),
        func.count(case((Document.rejection_reason.isnot(None), 1))).label('rejected_count'),
        func.count(Document.id).label('total_docs_count')
    ).filter(Document.doc_type.in_(required_doc_types)).group_by(Document.student_id).subquery()

    # Now, use the subquery to determine clearance status counts
    # This correctly ignores students with no documents
    approved_clearances_students_count = db.session.query(subquery).filter(
        subquery.c.approved_count == num_required_docs,
        subquery.c.rejected_count == 0
    ).count()

    rejected_clearances_students_count = db.session.query(subquery).filter(
        subquery.c.rejected_count > 0
    ).count()

    # Pending are those with documents but are not fully approved or rejected
    pending_clearances_students_count = db.session.query(subquery).filter(
        subquery.c.approved_count < num_required_docs,
        subquery.c.rejected_count == 0
    ).count()

    # --- END FIX: Optimized Clearance Status Counts ---

    # --- START FIX: Optimized Data for Review Table ---
    # Fetch students who have uploaded at least one required document,
    # ordered by the most recent document upload time.
    students_with_docs_query = db.session.query(Student)\
        .join(Document, Student.id == Document.student_id)\
        .filter(Document.doc_type.in_(required_doc_types))\
        .group_by(Student.id)\
        .order_by(desc(func.max(Document.uploaded_at)))

    # Fetch the students and their documents in a single, efficient query
    # to avoid the N+1 problem from the previous version.
    students_for_review_list = students_with_docs_query.all()

    students_data_for_template = []
    for student in students_for_review_list:
        student_documents = Document.query.filter(
            Document.student_id == student.id,
            Document.doc_type.in_(required_doc_types)
        ).order_by(desc(Document.uploaded_at)).all()

        student_info = {
            'student': student,
            'documents': []
        }
        existing_docs_by_type = {d.doc_type: d for d in student_documents}
        
        for doc_type in required_doc_types:
            doc_object = existing_docs_by_type.get(doc_type)
            student_info['documents'].append({
                'doc_type_display': doc_type.replace('_', ' ').title(),
                'doc_object': doc_object
            })
        students_data_for_template.append(student_info)
    # --- END FIX: Optimized Data for Review Table ---


    # --- START FIX: Recent Activities Card ---
    # This section was already good, just minor clarification
    recent_activities_db = ActivityLog.query.order_by(desc(ActivityLog.timestamp)).limit(10).all()
    recent_activities = []
    
    # ... (the time_ago function is the same, no need to repeat here)

    def time_ago(dt):
        now = datetime.utcnow()
        diff = now - dt
        seconds = diff.total_seconds()
        minutes = seconds / 60
        hours = minutes / 60
        days = diff.days

        if seconds < 60:
            return "just now"
        elif minutes < 60:
            return f"{int(minutes)} minute{'s' if minutes != 1 else ''} ago"
        elif hours < 24:
            return f"{int(hours)} hour{'s' if hours != 1 else ''} ago"
        elif days < 7:
            return f"{int(days)} day{'s' if days != 1 else ''} ago"
        else:
            return dt.strftime('%b %d, %Y %H:%M')
    
    for activity in recent_activities_db:
        recent_activities.append({
            'description': activity.action,
            'timestamp': time_ago(activity.timestamp)
        })
    # --- END FIX: Recent Activities Card ---

    # Calculate percentages for the overview cards based on STUDENT counts
    total_students_with_clearance_status = approved_clearances_students_count + pending_clearances_students_count + rejected_clearances_students_count
    pending_percentage = (pending_clearances_students_count / total_students_with_clearance_status * 100) if total_students_with_clearance_status else 0
    approved_percentage = (approved_clearances_students_count / total_students_with_clearance_status * 100) if total_students_with_clearance_status else 0
    rejected_percentage = (rejected_clearances_students_count / total_students_with_clearance_status * 100) if total_students_with_clearance_status else 0


    return render_template('admin_dashboard.html',
                           total_students=total_students,
                           pending_clearances=pending_clearances_students_count,
                           approved_clearances=approved_clearances_students_count,
                           rejected_clearances=rejected_clearances_students_count,
                           students_with_docs=students_data_for_template,
                           pending_percentage=pending_percentage,
                           approved_percentage=approved_percentage,
                           rejected_percentage=rejected_percentage,
                           recent_activities=recent_activities,
                           current_year=datetime.now().year)


@main.route('/admin/update_document_status/<int:document_id>/<status>', methods=['POST'])
@admin_required
def update_document_status(document_id, status):
    document = Document.query.get_or_404(document_id)
    student = document.student # Get the student associated with this document

    rejection_reason = None
    if status == 'reject':
        rejection_reason = request.form.get('rejection_reason')
        if not rejection_reason: # Make reason mandatory for rejection
            # For AJAX, return JSON error
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': False, 'message': 'Rejection reason is required for rejecting a document.'}), 400
            flash('Rejection reason is required for rejecting a document.', 'danger')
            return redirect(url_for('main.admin_dashboard'))

    # Store original status for activity logging detail
    original_doc_verified = document.verified
    original_doc_rejection_reason = document.rejection_reason


    if status == 'approve':
        document.verified = True
        document.rejection_reason = None
        message = f'Document "{document.doc_type.replace("_", " ").title()}" for {student.full_name} approved.'
        flash_category = 'success'
        activity_action = f"Admin approved '{document.doc_type.replace('_', ' ').title()}' for {student.full_name} ({student.registration_number})"
    elif status == 'reject':
        document.verified = False
        document.rejection_reason = rejection_reason
        message = f'Document "{document.doc_type.replace("_", " ").title()}" for {student.full_name} rejected.'
        flash_category = 'warning'
        activity_action = f"Admin rejected '{document.doc_type.replace('_', ' ').title()}' for {student.full_name} ({student.registration_number}) - Reason: {rejection_reason}"
    else:
        # For AJAX, return JSON error
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'message': 'Invalid status action.'}), 400
        flash('Invalid status action.', 'danger')
        return redirect(url_for('main.admin_dashboard'))

    db.session.commit() # Commit the document status change


    # --- Re-evaluate Student's Overall Clearance Status and log changes---
    required_docs = ['school_fee', 'accommodation', 'id_or_admission', 'passport']
    all_student_documents = Document.query.filter_by(student_id=student.id).all()

    is_fully_approved = True
    is_any_rejected = False
    is_any_pending_or_unuploaded = False

    for r_doc_type in required_docs:
        found_doc = next((d for d in all_student_documents if d.doc_type == r_doc_type), None)
        if not found_doc: # Document not even uploaded
            is_fully_approved = False
            is_any_pending_or_unuploaded = True
            # No break here, continue to find other rejections/pendings
        elif not found_doc.verified: # Document uploaded but not verified
            is_fully_approved = False
            if found_doc.rejection_reason:
                is_any_rejected = True # Document explicitly rejected
            else:
                is_any_pending_or_unuploaded = True # Document is pending review

    # Get or create the Clearance record for this student
    clearance = Clearance.query.filter_by(student_id=student.id).first()
    if not clearance:
        clearance = Clearance(student_id=student.id, clearance_type='Full Clearance') # Default type
        db.session.add(clearance)

    original_overall_clearance_status = clearance.status # Capture before changing

    if is_fully_approved:
        clearance.status = 'approved'
        clearance.verified = True
        clearance.cleared_at = datetime.utcnow()
    elif is_any_rejected:
        clearance.status = 'rejected'
        clearance.verified = False
        clearance.cleared_at = None
    elif is_any_pending_or_unuploaded:
        clearance.status = 'pending'
        clearance.verified = False
        clearance.cleared_at = None
    else: # Fallback, should align with pending if no documents or issues
        clearance.status = 'pending'
        clearance.verified = False
        clearance.cleared_at = None


    # Log overall clearance status change if it actually changed
    if clearance.status != original_overall_clearance_status:
        notification_message = ""
        activity_action_overall = ""
        if clearance.status == 'approved':
            notification_message = f'Congratulations, {student.first_name}! Your overall hostel clearance has been approved!'
            activity_action_overall = f"Overall clearance status changed to 'Approved' for {student.full_name} ({student.registration_number})"
        elif clearance.status == 'rejected':
            notification_message = f'Important: Your overall hostel clearance has been rejected due to outstanding document issues. Please check your dashboard for details and re-upload required documents.'
            activity_action_overall = f"Overall clearance status changed to 'Rejected' for {student.full_name} ({student.registration_number})"
        elif clearance.status == 'pending' and original_overall_clearance_status != 'pending':
            notification_message = f'Your overall hostel clearance status has been updated to pending. Please check your dashboard for details.'
            activity_action_overall = f"Overall clearance status changed to 'Pending' for {student.full_name} ({student.registration_number})"

        if notification_message:
            new_notification = Notification(student_id=student.id, message=notification_message)
            db.session.add(new_notification)
        if activity_action_overall:
            new_activity_overall = ActivityLog(admin_id=session['admin_id'], action=activity_action_overall)
            db.session.add(new_activity_overall)

    # Log the specific document action
    new_activity_doc = ActivityLog(admin_id=session['admin_id'], action=activity_action)
    db.session.add(new_activity_doc)

    db.session.commit()

    # For AJAX requests, return a JSON response
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'success': True, 'message': message, 'new_status': status})

    flash(message, flash_category)
    return redirect(url_for('main.admin_dashboard'))


@main.route('/admin/students')
@admin_required
def admin_students():
    students = Student.query.order_by(Student.created_at.desc()).all()
    return render_template('admin_students.html', students=students)


@main.route('/student/<int:student_id>')
@admin_required
def view_student(student_id):
    student = Student.query.get_or_404(student_id)
    documents = Document.query.filter_by(student_id=student.id).all()
    
    # Retrieve the overall clearance status for this student
    # Assuming there's a Clearance model related to the student
    overall_clearance_status = Clearance.query.filter_by(student_id=student.id).first()

    return render_template('view_student.html', 
                           student=student, 
                           documents=documents,
                           overall_clearance_status=overall_clearance_status) # Pass the overall status

@main.route('/admin/delete_student/<int:student_id>', methods=['POST'])
@admin_required
def delete_student(student_id):
    student = Student.query.get_or_404(student_id)
    
    # Log the action
    new_activity = ActivityLog(admin_id=session['admin_id'], action=f"Admin deleted student '{student.full_name}' ({student.registration_number}).")
    db.session.add(new_activity)

    db.session.delete(student)
    db.session.commit()
    flash('Student account and all associated data deleted successfully.', 'success')
    return redirect(url_for('main.admin_students'))


@main.route('/admin/activities')
@admin_required
def admin_activities():
    # Fetch all activities, with related student/admin info
    activities = ActivityLog.query.order_by(desc(ActivityLog.timestamp)).all()
    
    # For a more detailed view, we can pre-fetch related user objects
    for activity in activities:
        if activity.student_id:
            activity.user = Student.query.get(activity.student_id)
        elif activity.admin_id:
            activity.user = Admin.query.get(activity.admin_id)

    return render_template('admin_activities.html', activities=activities)

#####Manage students#########
@main.route('/manage_students')
@admin_required
def manage_students():
    # Fetch all students from the database
    students = Student.query.all()
    
    return render_template('manage_students.html', students=students)

###view student info####

@main.route('/student/<int:student_id>')
@admin_required
def view_student_info(student_id):
    student = Student.query.get_or_404(student_id)
    documents = Document.query.filter_by(student_id=student.id).all()
    return render_template('view_student.html', student=student, documents=documents)

@main.route('/student/delete/<int:student_id>', methods=['POST'])
@admin_required
def delete_student_info(student_id):
    student = Student.query.get_or_404(student_id)
    
    # First, delete all associated clearance records
    Clearance.query.filter_by(student_id=student_id).delete()

    # Now, delete all associated notification records
    Notification.query.filter_by(student_id=student_id).delete()

    # Then, delete the student from the database
    db.session.delete(student)
    db.session.commit()
    
    flash(f'Student {student.full_name} has been deleted successfully.', 'success')
    return redirect(url_for('main.manage_students'))
@main.route('/admin/logout')
@admin_required
def admin_logout():
    admin = Admin.query.get(session['admin_id'])
    if admin:
        new_activity = ActivityLog(admin_id=admin.id, action=f"Admin '{admin.username}' logged out.")
        db.session.add(new_activity)
        db.session.commit()
    session.pop('admin_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.admin_login'))