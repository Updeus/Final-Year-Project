from werkzeug.security import check_password_hash, generate_password_hash
from App.database import db
from flask import jsonify
from flask_login import UserMixin
from flask_user import login_required, UserManager, UserMixin
from datetime import datetime

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username =  db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(120), nullable=False)
    db.relationship('Role', secondary='UserRoles')
    email = db.Column(db.String(200), nullable=False, unique=True)

    def __init__(self, username, password, email):
        self.username = username
        self.set_password(password)
        self.email = email

    def toJSON(self):
        return{
            'id': self.id,
            'username': self.username,
            'password': self.password,
            'email': self.email
        }
    

    def set_password(self, password):
        """Create hashed password."""
        self.password = generate_password_hash(password, method='sha256')
    
    def check_password(self, password):
        """Check hashed password."""
        return check_password_hash(self.password, password)