#  IRIS Source Code
#  Copyright (C) 2021 - Airbus CyberSecurity (SAS)
#  ir@cyberactionlab.net
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public
#  License as published by the Free Software Foundation; either
#  version 3 of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with this program; if not, write to the Free Software Foundation,
#  Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

from flask import Blueprint
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for
from flask_login import current_user
from flask_login import logout_user
from flask_wtf import FlaskForm

from app import app
from app import db
from app.datamgmt.dashboard.dashboard_db import get_tasks_status
from app.forms import CaseGlobalTaskForm
from app.iris_engine.access_control.utils import ac_get_user_case_counts
from app.iris_engine.utils.tracker import track_activity
from app.models.authorization import User
from app.models.models import GlobalTasks
from app.util import ac_api_requires
from app.util import ac_requires
from app.util import not_authenticated_redirection_url

dashboard_blueprint = Blueprint(
    'index',
    __name__,
    template_folder='templates'
)


# Logout user
@dashboard_blueprint.route('/logout')
def logout():
    """
    Logout function. Erase its session and redirect to index i.e login
    :return: Page
    """
    if session['current_case']:
        current_user.ctx_case = session['current_case']['case_id']
        current_user.ctx_human_case = session['current_case']['case_name']
        db.session.commit()

    track_activity("user '{}' has been logged-out".format(current_user.user), ctx_less=True, display_in_ui=False)
    logout_user()
    session.clear()

    return redirect(not_authenticated_redirection_url('/'))


@dashboard_blueprint.route('/')
def root():
    if app.config['DEMO_MODE_ENABLED'] == 'True':
        return redirect(url_for('demo-landing.demo_landing'))

    return redirect(url_for('index.index'))


@dashboard_blueprint.route('/dashboard')
@ac_requires()
def index(caseid, url_redir):
    """
    Index page. Load the dashboard data, create the add customer form
    :return: Page
    """
    if url_redir:
        return redirect(url_for('index.index', cid=caseid if caseid is not None else 1, redirect=True))

    msg = None

    acgucc = ac_get_user_case_counts(current_user.id)

    data = {
        "user_open_count": acgucc[2],
        "cases_open_count": acgucc[1],
        "cases_count": acgucc[0],
    }

    # Create the customer form to be able to quickly add a customer
    form = FlaskForm()

    return render_template('index.html', data=data, form=form, msg=msg)


@dashboard_blueprint.route('/global/tasks/add/modal', methods=['GET'])
@ac_api_requires()
def add_gtask_modal():
    task = GlobalTasks()

    form = CaseGlobalTaskForm()

    form.task_assignee_id.choices = [(user.id, user.name) for user in User.query.filter(User.active == True).order_by(User.name).all()]
    form.task_status_id.choices = [(a.id, a.status_name) for a in get_tasks_status()]

    return render_template("modal_add_global_task.html", form=form, task=task, uid=current_user.id, user_name=None)


@dashboard_blueprint.route('/global/tasks/update/<int:cur_id>/modal', methods=['GET'])
@ac_api_requires()
def edit_gtask_modal(cur_id):
    form = CaseGlobalTaskForm()
    task = GlobalTasks.query.filter(GlobalTasks.id == cur_id).first()
    form.task_assignee_id.choices = [(user.id, user.name) for user in
                                     User.query.filter(User.active == True).order_by(User.name).all()]
    form.task_status_id.choices = [(a.id, a.status_name) for a in get_tasks_status()]

    # Render the task
    form.task_title.render_kw = {'value': task.task_title}
    form.task_description.data = task.task_description
    user_name, = User.query.with_entities(User.name).filter(User.id == task.task_userid_update).first()

    return render_template("modal_add_global_task.html", form=form, task=task,
                           uid=task.task_assignee_id, user_name=user_name)
