import unittest
from flask import url_for
from flask_testing import TestCase
from App.main import create_app, db
from App.database import create_db
from App.models import User, Role, Task
import logging

from wsgi import app


LOGGER = logging.getLogger(__name__)

class TestUserViews(TestCase):

    def create_app(self):
        app = create_app()
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
        return app

    def setUp(self):
        db.create_all()
        self.user = User(username='testuser', email='test@example.com', password='testpassword')
        self.admin_role = Role(name='Admin')
        self.user.roles.append(self.admin_role)
        db.session.add(self.user)
        db.session.add(self.admin_role)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()

    def login(self, username, password):
        return self.client.post(
            url_for('user_views.login'),
            data={'username': username, 'password': password},
            follow_redirects=True
        )

    def test_landing_page(self):
        response = self.client.get(url_for('user_views.landing'))
        self.assert200(response)
        self.assert_template_used('landing.html')

    def test_login(self):
        response = self.login('testuser', 'testpassword')
        self.assert200(response)
        self.assert_template_used('home.html')

    def test_login_invalid_credentials(self):
        response = self.login('wronguser', 'wrongpassword')
        self.assert200(response)
        self.assert_template_used('login.html')

    def test_logout(self):
        self.login('testuser', 'testpassword')
        response = self.client.get(url_for('user_views.logout'), follow_redirects=True)
        self.assert200(response)
        self.assert_template_used('login.html')

    def test_home_page(self):
        self.login('testuser', 'testpassword')
        response = self.client.get(url_for('user_views.home'))
        self.assert200(response)
        self.assert_template_used('home.html')

    # Add additional tests for your other views here
    # ...

if __name__ == '__main__':
    unittest.main()
