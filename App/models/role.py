from App.database import db
from datetime import datetime
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import UserMixin

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)


