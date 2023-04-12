import io
from datetime import datetime
from xhtml2pdf import pisa
from flask import render_template_string
from App.models.task import Task
from App.models.user import User

def get_tasks_for_report_type(report_type, task_id, start_date, end_date, current_user, user_id=None, role_id=None):
    if report_type == 'full_committee':
        if current_user.has_roles('Admin') and role_id:
            tasks = Task.query.filter(Task.role_id == role_id, Task.due_date >= start_date, Task.due_date <= end_date).all()
        elif current_user.has_roles('Admin'):
            tasks = Task.query.filter(Task.due_date >= start_date, Task.due_date <= end_date).all()
        else:
            tasks = []
            user_roles = current_user.roles
            for role in user_roles:
                role_tasks = Task.query.filter(Task.role_id == role.id, Task.due_date >= start_date, Task.due_date <= end_date).all()
                tasks.extend(role_tasks)
    elif report_type == 'singular_task':
        task = Task.query.get(task_id)
        tasks = [task] if task else []
    elif report_type == 'singular_user':
        user = User.query.get(user_id) if user_id else current_user
        tasks = Task.query.filter(Task.assignments.any(id=user.id), Task.due_date >= start_date, Task.due_date <= end_date).all()
    else:
        tasks = []
    return tasks


def get_all_tasks_for_user(user):
    if user.has_roles('Admin'):
        tasks = Task.query.all()
    else:
        tasks = user.assigned_tasks
    return tasks

def generate_pdf_report(tasks, report_type, current_user):
    template = """
<html>

<head>
  <style>
    table,
    th,
    td {
      border: 1px solid black;
      border-collapse: collapse;
    }

    th,
    td {
      padding: 5px;
    }
  </style>
</head>

<body>
  <h1>Task Report</h1>
  <p>Report generated on: {{ now }}</p>
  {% if group_by_status %}
  {% for status in ['To Do', 'Ongoing', 'Completed'] %}
  <h2>Status: {{ status }}</h2>
  <table>
    <tr>
      <th>Committee</th>
      <th>Title</th>
      <th>Description</th>
      <th>Due Date</th>
      <th>Assigned Date</th>
      <th>Assigned Users</th>
      <th>Status</th>
    </tr>
    {% for task in tasks if task.status == status %}
    <tr>
      <td>{{ task.role.name }}</td>
      <td>{{ task.title }}</td>
      <td>{{ task.description }}</td>
      <td>{{ task.due_date.strftime('%Y-%m-%d') }}</td>
      <td>{{ task.assigned_date.strftime('%Y-%m-%d') }}</td>
      <td>{% for user in task.assignments %}{{ user.username }}{% if not loop.last %}, {% endif %}{% endfor %}</td>
      <td>{{ task.status }}</td>
    </tr>
    {% endfor %}
  </table>
  {% endfor %}
  {% else %}
  <table>
    <tr>
      <th>Committee</th>
      <th>Title</th>
      <th>Description</th>
      <th>Due Date</th>
      <th>Assigned Date</th>
      <th>Assigned Users</th>
      <th>Status</th>
    </tr>
    {% for task in tasks %}
    <tr>
      <td>{{ task.role.name }}</td>
      <td>{{ task.title }}</td>
      <td>{{ task.description }}</td>
      <td>{{ task.due_date.strftime('%Y-%m-%d') }}</td>
      <td>{{ task.assigned_date.strftime('%Y-%m-%d') }}</td>
      <td>{% for user in task.assignments %}{{ user.username }}{% if not loop.last %}, {% endif %}{% endfor %}</td>
      <td>{{ task.status }}</td>
    </tr>
    {% endfor %}
  </table>
  {% endif %}
  {% if include_comments %}
  {% for task in tasks %}
  <h3>{{ task.title }}</h3>
  <h4>Comments:</h4>
  <ul>
    {% for comment in task.comments %}
    <li>{{ comment.user.username }}: {{ comment.content }}</li>
    {% endfor %}
  </ul>
  {% endfor %}
  {% endif %}
</body>

</html>
    """
    group_by_status = report_type == 'full_committee'
    include_comments = report_type == 'singular_task'

    html = render_template_string(template, tasks=tasks, now=datetime.now().strftime('%Y-%m-%d %H:%M:%S'), group_by_status=group_by_status, include_comments=include_comments)
    pdf_file = io.BytesIO()

    pisa.CreatePDF(html, dest=pdf_file)

    return pdf_file.getvalue()
