from App.models import User, Role
from flask_sqlalchemy import SQLAlchemy
from App.database import db
from flask_user import login_required, UserManager, UserMixin



def createAdmin():
    if user := get_user_by_username('Admin'):
        return None
    admin_role = Role(name='Admin')
    db.session.add(admin_role)
    db.session.commit()
    admin = User(
    username='Admin', password='Password1', email='admin@example.com')
    db.session.add(admin)
    db.session.commit()
    admin.roles = get_role_by_name('Admin')
    db.session.commit()
    return

def get_role_by_name(name):
    return Role.query.filter_by(name=name).first()

def create_user(username, password, email):
    newuser = User(username=username, password=password, email=email)
    db.session.add(newuser)
    db.session.commit()
    return newuser

def get_user_by_username(username):
    user = User.query.filter_by(username=username).first()
    if user:
        user = user.toJSON()
    return user




def get_user(id):
    return User.query.get(id)

def get_all_users():
    return User.query.all()

def get_all_users_json():
    users = User.query.all()
    if not users:
        return []
    users = [user.toJSON() for user in users]
    return users

def update_user(id, username):
    if user := get_user(id):
        user.username = username
        db.session.add(user)
        db.session.commit()
        return user
    return None

def delete_user(id):
    if user := get_user(id):
        db.session.delete(user)
        return db.session.commit()
    return None