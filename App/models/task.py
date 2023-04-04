from App.database import db
from datetime import datetime
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import UserMixin
from App.models import User

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(80), nullable=False)
    description = db.Column(db.Text, nullable=True)
    due_date = db.Column(db.DateTime, nullable=True)
    assigned_users = db.relationship('User', secondary='task_assignments')
    status = db.Column(db.String(20), default="To Do")
    role = db.relationship('Role', backref='tasks')
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=True) #remove nullable=True if problems 
    role = db.relationship('Role', backref=db.backref('tasks', lazy=True))
    comments = db.relationship('Comment', back_populates='task')

task_assignments = db.Table('task_assignments',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('task_id', db.Integer, db.ForeignKey('task.id'), primary_key=True)
)

def get_user_role_tasks(user_id):
    user = User.query.get(user_id)
    user_role_tasks = []
    for role in user.roles:
        role_tasks = Task.query.filter_by(role_id=role.id).all()
        user_role_tasks.extend(role_tasks)
    return user_role_tasks

def get_tasks_by_user(user_id):
    return Task.query.filter_by(assigned_user_id=user_id).all()