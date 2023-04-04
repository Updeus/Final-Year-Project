from App.database import db
from datetime import datetime
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import UserMixin
from App.models import User



role_members = db.Table('role_members',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True)
)

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    leader_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    leader = db.relationship('User', backref=db.backref('leader_role', uselist=False))
    members = db.relationship('User', secondary=role_members, backref=db.backref('member_roles', lazy='dynamic'))

