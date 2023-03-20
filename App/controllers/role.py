from App.models import User, Role
from flask_sqlalchemy import SQLAlchemy
from App.database import db
from flask_user import login_required, UserManager, UserMixin

