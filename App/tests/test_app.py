import os, tempfile, pytest, logging, unittest
from werkzeug.security import check_password_hash, generate_password_hash

from App.main import create_app
from App.database import create_db
from App.models import User
from App.controllers import (
    create_user,
    get_all_users_json,
    authenticate,
    get_user,
    get_user_by_username,
    update_user
)

from wsgi import app


LOGGER = logging.getLogger(__name__)

'''
   Unit Tests
'''
class UserUnitTests(unittest.TestCase):
    def test_new_user(self):
        user = User("bob", "bob@example.com", "bobpass")
        self.assertEqual(user.username, "bob")

    def test_toJSON(self):
        user = User("bob", "bob@example.com", "bobpass")
        self.assertEqual(user.toJSON(), {"id": None, "username": "bob", "email": "bob@example.com"})

    def test_hashed_password(self):
        password = "mypass"
        user = User("bob", "bob@example.com", password)
        self.assertNotEqual(user.password, password)
        self.assertTrue(user.check_password(password))


    def test_check_password(self):
        password = "mypass"
        user = User("bob", "bob@example.com", password)
        self.assertTrue(user.check_password(password))
        self.assertFalse(user.check_password("wrongpass"))


'''
    Integration Tests
'''

# This fixture creates an empty database for the test and deletes it after the test
# scope="class" would execute the fixture once and resued for all methods in the class
@pytest.fixture(autouse=True, scope="module")
def empty_db():
    app.config.update({'TESTING': True, 'SQLALCHEMY_DATABASE_URI': 'sqlite:///test.db'})
    create_db(app)
    yield app.test_client()
    os.unlink(f'{os.getcwd()}/App/test.db')

class UsersIntegrationTests(unittest.TestCase):

    def test_create_user(self):
        user = create_user("rick", "rickpass", "rick@example.com")
        assert user.username == "rick"

    def test_get_all_users_json(self):
        users_json = get_all_users_json()
        self.assertListEqual(
            [
                {'id': 1, 'username': 'rick', 'email': 'rick@example.com'}
            ],
            users_json,
        )


    # Tests data changes in the database
    def test_update_user(self):
        update_user(1, "ronnie")
        user = get_user(1)
        assert user.username == "ronnie"
