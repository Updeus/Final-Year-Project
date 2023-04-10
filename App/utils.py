import io
from datetime import datetime
from xhtml2pdf import pisa
from flask import render_template_string

def generate_pdf_report(tasks):
    template = """
    <html>
    <head>
        <style>
            table, th, td {
                border: 1px solid black;
                border-collapse: collapse;
            }
            th, td {
                padding: 5px;
            }
        </style>
    </head>
    <body>
        <h1>Task Report</h1>
        <p>Report generated on: {{ now }}</p>
        <table>
            <tr>
                <th>Role</th>
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
        {% for task in tasks %}
            <h3>{{ task.title }}</h3>
            <h4>Comments:</h4>
            <ul>
            {% for comment in task.comments %}
                <li>{{ comment.user.username }}: {{ comment.content }}</li>
            {% endfor %}
            </ul>
        {% endfor %}
    </body>
</html>
    """

    html = render_template_string(template, tasks=tasks, now=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    pdf_file = io.BytesIO()

    pisa.CreatePDF(html, dest=pdf_file)

    return pdf_file.getvalue()
