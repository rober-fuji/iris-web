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
from flask import url_for
from flask_wtf import FlaskForm

from app import app
from app.datamgmt.manage.manage_srv_settings_db import get_srv_settings
from app.util import ac_requires
from app.util import endpoint_removed

profile_blueprint = Blueprint('profile',
                              __name__,
                              template_folder='templates')


@profile_blueprint.route('/user/settings', methods=['GET'])
@ac_requires(no_cid_required=True)
def user_settings(caseid, url_redir):
    if url_redir:
        return redirect(url_for('profile.user_settings', cid=caseid))

    return render_template('profile.html', mfa_enabled=app.config.get('MFA_ENABLED', False))


@profile_blueprint.route('/user/is-admin', methods=['GET'])
@endpoint_removed('Use /user/has-permission to check permission', 'v1.5.0')
def user_is_admin(caseid):
    pass


@profile_blueprint.route('/user/update/modal', methods=['GET'])
@ac_requires(no_cid_required=True)
def update_pwd_modal(caseid, url_redir):
    if url_redir:
        return redirect(url_for('profile.user_settings', cid=caseid))

    form = FlaskForm()

    server_settings = get_srv_settings()

    return render_template("modal_pwd_user.html", form=form, server_settings=server_settings)
