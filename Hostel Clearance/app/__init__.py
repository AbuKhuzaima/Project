import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

from flask_migrate import Migrate


db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__, instance_relative_config=True)
    migrate = Migrate(app, db)
    app.config['SECRET_KEY'] = 'kadera'

    db_path = os.path.join(app.instance_path, 'hostel.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    try:
        os.makedirs(app.instance_path, exist_ok=True)
    except OSError:
        pass

    # ✅ Create static/uploads directory if not exists
    upload_path = os.path.join(app.root_path, 'static', 'uploads')
    try:
        os.makedirs(upload_path, exist_ok=True)
    except OSError:
        pass


    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'main.student_login'

    # ✅ Delay import to avoid circular import
    @login_manager.user_loader
    def load_user(user_id):
        from app.models import Student
        return Student.query.get(int(user_id))

    # ✅ Now it's safe to register the blueprint
    from app.routes import main
    app.register_blueprint(main)

    with app.app_context():
        db.create_all()

    return app
