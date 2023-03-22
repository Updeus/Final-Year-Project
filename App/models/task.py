from App.database import db
from datetime import datetime
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import UserMixin

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(80), nullable=False)
    description = db.Column(db.Text, nullable=True)
    due_date = db.Column(db.DateTime, nullable=True)
    assigned_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    assigned_user = db.relationship('User', backref=db.backref('tasks', lazy='dynamic'))