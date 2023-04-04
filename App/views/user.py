import os
from flask import Blueprint, Flask, request, jsonify, render_template, redirect, url_for, flash, send_from_directory, json
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from App.database import db
from App.models import User, Role, Task, UserRoles, Comment
from App.models.task import get_user_role_tasks, get_tasks_by_user
from datetime import datetime
from sqlalchemy import and_


ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

user_views = Blueprint('user_views', __name__, template_folder='../templates')


@user_views.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('user_views.home'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('user_views.home'))
        else:
            flash('Invalid username or password.')

    return render_template('login.html')

@user_views.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('user_views.login'))


@user_views.route('/admin/assign_task', methods=['GET', 'POST'])
@login_required
def assign_task():
    if request.method == 'GET':
        roles = Role.query.all()
        return render_template('assign_task.html', roles=roles)

    role_name = request.form.get('role_name')
    title = request.form.get('title')
    description = request.form.get('description')
    due_date = datetime.strptime(request.form.get('due_date'), '%Y-%m-%d')
    role = Role.query.filter_by(name=role_name).first()

    for user in role.users:
        task = Task(title=title, description=description, due_date=due_date)
        task.assigned_user = user
        task.role = role
        db.session.add(task)

    db.session.commit()

    return redirect(url_for('user_views.view_tasks'))


@user_views.route('/tasks', methods=['GET'])
@login_required
def view_tasks():
    date = request.args.get('date')

    if current_user.has_roles('Admin'):
        tasks = Task.query.all()
    else:
        tasks = get_user_role_tasks(current_user.id)
        role_leader_tasks = Task.query.join(Task.role).filter(and_(Role.leader_id == current_user.id, Task.assigned_users.any(User.id != current_user.id))).all()
        tasks = [task for task in tasks if task not in role_leader_tasks]

    if date:
        tasks = [task for task in tasks if task.due_date == date]

    # Filter out duplicate tasks
    unique_tasks = []
    seen_tasks = set()
    for task in tasks:
        task_key = (task.title, task.description, task.due_date)
        if task_key not in seen_tasks:
            unique_tasks.append(task)
            seen_tasks.add(task_key)

    tasks = unique_tasks

    if not tasks:
        return render_template('no_tasks.html')
    else:
        return render_template('tasks.html', tasks=tasks)


@user_views.route('/')
def home():
    return render_template('home.html')

@user_views.route('/admin/remove_task', methods=['GET', 'POST'])
@login_required
def remove_task():
    if not current_user.has_roles('Admin'):
        flash('You are not authorized to access this page.')
        return redirect(url_for('user_views.home'))

    roles = Role.query.all()
    tasks = Task.query.all()

    if request.method == 'POST':
        task_id = request.form.get('task_id')
        task = Task.query.get(task_id)

        if task:
            db.session.delete(task)
            db.session.commit()
            flash('Task removed successfully.')
        else:
            flash('Task not found.')

    return render_template('remove_task.html', roles=roles, tasks=tasks)


@user_views.route('/admin/create_role', methods=['GET', 'POST'])
@login_required
def create_role():
    if not current_user.has_roles('Admin'):
        flash('You are not authorized to access this page.')
        return redirect(url_for('user_views.home'))

    if request.method == 'POST':
        role_name = request.form.get('role_name')
        existing_role = Role.query.filter_by(name=role_name).first()

        if existing_role:
            flash('Role already exists.')
        else:
            new_role = Role(name=role_name)
            db.session.add(new_role)
            db.session.commit()
            flash('Role created successfully.')

    return render_template('create_role.html')


@user_views.route('/admin/remove_role', methods=['GET', 'POST'])
@login_required
def remove_role():
    if not current_user.has_roles('Admin'):
        flash('You are not authorized to access this page.')
        return redirect(url_for('user_views.home'))

    roles = Role.query.all()

    if request.method == 'POST':
        role_id = request.form.get('role_id')
        role = Role.query.get(role_id)

        if role:
            db.session.delete(role)
            db.session.commit()
            flash('Role removed successfully.')
        else:
            flash('Role not found.')

        roles = Role.query.all()

    return render_template('remove_role.html', roles=roles)


@user_views.route('/user/settings', methods=['GET', 'POST'])
@login_required
def user_settings():
    if request.method == 'POST':
        new_username = request.form.get('username')
        new_email = request.form.get('email')
        new_password = request.form.get('password')

        if new_username:
            current_user.username = new_username

        if new_email:
            current_user.email = new_email

        if new_password:
            current_user.password = generate_password_hash(new_password)

        db.session.commit()
        flash('Settings updated successfully.')

    return render_template('user_settings.html')


@user_views.route('/admin/remove_user_role', methods=['GET', 'POST'])
@login_required
def remove_user_role():
    if not current_user.has_roles('Admin'):
        flash('You are not authorized to access this page.')
        return redirect(url_for('user_views.home'))

    users = User.query.all()
    user_roles = {user.id: user.roles for user in users}

    if request.method == 'POST':
        user_id = request.form.get('user_id')
        role_id = request.form.get('role_id')

        user = User.query.get(user_id)
        role = Role.query.get(role_id)

        if user and role and role in user.roles:
            user.roles.remove(role)

            # Remove tasks associated with the removed role
            tasks_to_remove = Task.query.filter_by(assigned_user_id=user_id).join(Task.role).filter(Role.id == role_id).all()
            for task in tasks_to_remove:
                db.session.delete(task)

            db.session.commit()
            flash('Role removed from user successfully, and tasks associated with the role have been removed.')
        else:
            flash('Role not found for the selected user.')

    return render_template('remove_user_role.html', users=users, user_roles=user_roles)




@user_views.route('/admin/delegate_role', methods=['GET', 'POST'])
@login_required
def delegate_role():
    if not current_user.has_roles('Admin'):
        flash('You are not authorized to access this page.')
        return redirect(url_for('user_views.home'))

    users = User.query.all()
    roles = Role.query.all()

    if request.method == 'POST':
        user_id = request.form.get('user_id')
        role_id = request.form.get('role_id')
        is_role_leader = 'is_role_leader' in request.form

        user = User.query.get(user_id)
        role = Role.query.get(role_id)

        if user and role:
            user.roles.append(role)

            if is_role_leader:
                role.leader = user

            db.session.commit()
            flash('Role delegated to user successfully.')
        else:
            flash('Error delegating role.')

    return render_template('delegate_role.html', users=users, roles=roles)



@user_views.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('user_views.view_tasks'))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()

        if existing_user:
            flash('Username or email already exists.')
        else:
            new_user = User(username=username, email=email, password=password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful. Please log in.')
            return redirect(url_for('user_views.login'))

    return render_template('signup.html')


@user_views.route('/tasks/<int:task_id>/comments', methods=['GET', 'POST'])
@login_required
def add_comment(task_id):
    task = Task.query.get(task_id)
    if not task or task.assigned_user_id != current_user.id:
        flash("You don't have permission to access this task.")
        return redirect(url_for('user_views.view_tasks'))

    if request.method == 'POST':
        content = request.form.get('content')
        attachment = request.files.get('attachment')

        print(f"Content: {content}")  # Debugging line

        if attachment and allowed_file(attachment.filename):
            filename = secure_filename(attachment.filename)
            attachment.save(os.path.join('App/uploads', filename))
        else:
            filename = None

        comment = Comment(content=content, user_id=current_user.id, task_id=task_id, attachment=filename)
        print(f"Comment: {comment}")
        db.session.add(comment)
        db.session.commit()
        print("Comment added to the database")
        flash('Comment added successfully.')
        return redirect(url_for('user_views.add_comment', task_id=task_id))

    comments = Comment.query.filter_by(task_id=task_id).order_by(Comment.timestamp.desc()).all()

    return render_template('tasks.html', task=task, comments=comments)



@user_views.route('/resources', methods=['GET'])
@login_required
def resources():
    if current_user.has_roles('Admin'):
        tasks = Task.query.all()
    else:
        tasks = get_tasks_by_user(current_user.id)
    
    # Create a list of events with start and end dates for each task
    events = []
    for task in tasks:
        event = {
            'title': task.title.replace("12a", ""),
            'start': task.due_date.isoformat().replace("12a", ""),
            'end': task.due_date.isoformat().replace("12a", ""),
        }
        events.append(event)
    
    # Convert the events list to a JSON object
    events_json = json.dumps(events)

    return render_template('resources.html', events=events_json)

@user_views.route('/tasks/comments/attachments/<path:filename>', methods=['GET'])
@login_required
def download_attachment(filename):
    try:
        return send_from_directory(directory='App/uploads', filename=filename, as_attachment=True)
    except FileNotFoundError:
        flash('The file was not found.')
        return redirect(request.referrer)


@user_views.route('/tasks/<int:task_id>/update_status', methods=['POST'])
@login_required
def update_status(task_id):
    task = Task.query.get(task_id)

    if not task or not (current_user.has_roles('Admin') or current_user.id == task.assigned_user_id):
        flash("You don't have permission to update this task.")
        return redirect(url_for('user_views.view_tasks'))

    new_status = request.form.get('status')

    if new_status not in ['To Do', 'Ongoing', 'Completed']:
        flash('Invalid status.')
        return redirect(request.referrer)

    task.status = new_status
    db.session.commit()

    flash('Task status updated successfully.')
    return redirect(url_for('user_views.view_tasks'))
