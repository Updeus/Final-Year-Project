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
    completed_date = db.Column(db.DateTime, nullable=True)
    assignments = db.relationship('User', secondary='task_assignments', backref='assigned_tasks')
    status = db.Column(db.String(20), default="To Do")
    role = db.relationship('Role', backref='tasks')
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=True) #remove nullable=True if problems 
    comments = db.relationship('Comment', back_populates='task')

    @property
    def assigned_date(self):
        user = self.assignments[0]  # Assuming at least one user is assigned to the task
        association = db.session.query(task_assignments).filter_by(user_id=user.id, task_id=self.id).first()
        return association.assigned_date

    @assigned_date.setter
    def assigned_date(self, value):
        user = self.assignments[0]  # Assuming at least one user is assigned to the task
        stmt = task_assignments.update().where(task_assignments.c.user_id == user.id).where(task_assignments.c.task_id == self.id).values(assigned_date=value)
        db.session.execute(stmt)

task_assignments = db.Table('task_assignments',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('task_id', db.Integer, db.ForeignKey('task.id'), primary_key=True),
    db.Column('assigned_date', db.DateTime, nullable=False, default=datetime.utcnow)  # Add comma at the end
)

def get_user_role_tasks(user_id):
    user = User.query.get(user_id)
    user_role_tasks = []
    for role in user.roles:
        role_tasks = Task.query.filter_by(role_id=role.id).all()
        user_role_tasks.extend(role_tasks)
    return user_role_tasks

def get_tasks_by_user(user_id):
    user = User.query.get(user_id)
    return user.assigned_tasks

