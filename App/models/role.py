from werkzeug.security import check_password_hash, generate_password_hash
from App.database import db
from flask import jsonify
from flask_login import UserMixin
from flask_user import login_required, UserManager, UserMixin
from datetime import datetime

class Role(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(50), unique=False)


    def toJSON(self):
        return{
            'id': self.id,
            'name': self.name
        }
