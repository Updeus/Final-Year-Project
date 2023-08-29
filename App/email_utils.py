import os
from cryptography.fernet import Fernet
from App.models import User
from flask_mail import Message
import requests
from App.database import db
from App.models import Task, task_assignments


def get_decrypted_value(key_name):
    # Load the encryption key from the "keys" folder
    with open(f"App/keys/{key_name}_key.txt", "rb") as key_file:
        encryption_key = key_file.read()

    # Load the encrypted value from the "keys" folder
    with open(f"App/keys/{key_name}_encrypted.txt", "rb") as encrypted_file:
        encrypted_value = encrypted_file.read()

    # Decrypt the value
    fernet = Fernet(encryption_key)
    return fernet.decrypt(encrypted_value).decode()

api_key = get_decrypted_value("MAILGUN_API_KEY")
api_base_url = get_decrypted_value("MAILGUN_API_BASE_URL")
domain = get_decrypted_value("MAILGUN_DOMAIN")

def send_email(mail, subject, recipients, body):
    msg = Message(subject, recipients=recipients)
    msg.body = body
    mail.send(msg)

def send_email_via_mailgun_api(to, subject, text):
    sender = f'mailgun@{domain}'

    return requests.post(
        f"https://api.mailgun.net/v3/{domain}/messages",
        auth=("api", api_key),
        data={"from": sender,
              "to": to,
              "subject": subject,
              "text": text})

def send_task_assignment_email(mail, task, user):
    if user and user.email:
        subject = f"New Task Assigned: {task.title}"
        body = f"Dear {user.username},\n\nYou have been assigned a new task: {task.title}\nDue Date: {task.due_date}\n\nTask Details: {task.description}\n\nPlease make sure to complete the task before the due date."
        send_email_via_mailgun_api([user.email], subject, body)

def send_due_date_reminder_email(task):
    if (
        task_assignment := db.session.query(task_assignments)
        .filter_by(task_id=task.id)
        .first()
    ):
        user = User.query.get(task_assignment.user_id)
        if user and user.email:
            subject = f"Task Due Date Reminder: {task.title}"
            body = f"Dear {user.username},\n\nThis is a reminder that the due date for your task '{task.title}' is due within 7 days.\n\nTask Details: {task.description}\n\nPlease make sure to complete the task as soon as possible."
            send_email_via_mailgun_api([user.email], subject, body)


