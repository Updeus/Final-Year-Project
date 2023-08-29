from App.models import User, Role, Task
import os
from flask import Flask, json, render_template
from flask_login import LoginManager, current_user, login_manager
from flask_uploads import DOCUMENTS, IMAGES, TEXT, UploadSet, configure_uploads
from flask_cors import CORS
from App.database import db
from werkzeug.utils import secure_filename
from werkzeug.datastructures import FileStorage
from datetime import timedelta
from flask_mail import Mail, Message
from .email_utils import send_task_assignment_email, send_due_date_reminder_email

from App.database import create_db, get_migrate

from App.controllers import (
    setup_jwt
)

from App.views import (
    user_views
)

views = [
    user_views
]

def add_views(app, views):
    for view in views:
        app.register_blueprint(view)

def loadConfig(app, config):
    app.config['ENV'] = os.environ.get('ENV', 'DEVELOPMENT')
    delta = 7
    if app.config['ENV'] == "DEVELOPMENT":
        app.config.from_object('App.config')
        delta = app.config['JWT_EXPIRATION_DELTA']
    else:
        app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI')
        app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
        app.config['DEBUG'] = os.environ.get('ENV').upper() != 'PRODUCTION'
        app.config['ENV'] = os.environ.get('ENV')
        delta = os.environ.get('JWT_EXPIRATION_DELTA', 7)

    app.config['USER_EMAIL_SENDER_EMAIL'] = os.environ.get('USER_EMAIL_SENDER_EMAIL', 'info3604taskassignment@gmail.com')
    app.config['JWT_EXPIRATION_DELTA'] = timedelta(days=int(delta))
    app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.mailgun.org')
    app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'postmaster@sandbox24c386880dc2424cb08ecffb534de668.mailgun.org')
    app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', '130cfabe5f42b4678b9bd0fc5f5a00bc-2cc48b29-91a468ac')


    for key, value in config.items():
        app.config[key] = config[key]
        
def create_admin_account(app):
    with app.app_context():
        admin_username = "Admin"
        admin_role_name = "Admin"

        admin_role = Role.query.filter_by(name=admin_role_name).first()
        if not admin_role:
            admin_role = Role(name=admin_role_name)
            db.session.add(admin_role)
            db.session.commit()

        admin = User.query.filter_by(username=admin_username).first()

        if not admin:
            admin_password = "Password1"
            admin_email = "admin@gmail.com"
            admin = User(
                username=admin_username,
                email=admin_email,
                password=admin_password
            )
            admin.roles.append(admin_role)
            db.session.add(admin)
            db.session.commit()

def create_roles(app):
    with app.app_context():
        role_names = [
            "Curriculum Review",
            "IT",
            "Entrance",
            "Graduate Studies and Research",
            "Examination Quality Assurance Committee (EQAC)",
            "Academic Advising Committee",
            "Timetable",
            "Library",
            "Health, Safety and Environment",
            "Building and Maintenance",
            "Prizes",
            "Outreach",
            "Industry Liaison",
        ]

        for role_name in role_names:
            role = Role.query.filter_by(name=role_name).first()
            if not role:
                role = Role(name=role_name)
                db.session.add(role)
                db.session.commit()
def create_app(config={}):
    app = Flask(__name__, static_url_path='/static')
    CORS(app)
    loadConfig(app, config)
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    app.config['PREFERRED_URL_SCHEME'] = 'https'
    app.config['UPLOADED_PHOTOS_DEST'] = "App/uploads"
    photos = UploadSet('photos', TEXT + DOCUMENTS + IMAGES)
    configure_uploads(app, photos)
    add_views(app, views)
    create_db(app)
    mail = Mail(app)
    app.mail = mail  # Attach the mail object to the app instance
    login_manager=LoginManager(app)
    login_manager.init_app(app)
    migrate=get_migrate(app)
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(user_id)
    setup_jwt(app)
    app.app_context().push()
    create_admin_account(app)
    create_roles(app)
    @app.template_filter('tojson')
    def tojson_filter(value):
        return json.dumps(value, default=str)

    app.jinja_env.filters['tojson'] = tojson_filter
    return app

app = create_app()
login_manager = LoginManager(app)
login_manager.init_app(app)
migrate = get_migrate(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)

