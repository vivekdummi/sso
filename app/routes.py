
from flask import Blueprint, render_template, session, request, redirect, url_for, flash, current_app, send_file, abort, jsonify
from functools import wraps
from flask_login import login_required, current_user
import os, shutil, zipfile
import json
import logging
import jwt
import requests


def role_required(*allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(403)

            # Convert role string to list (if needed)
            user_roles = current_user.role
            if isinstance(user_roles, str):
                user_roles = [role.strip() for role in user_roles.split(',')]

            # Check if user has any allowed role
            if not any(role in user_roles for role in allowed_roles):
                abort(403)

            return f(*args, **kwargs)

        return decorated_function

    return decorator


main = Blueprint('main', __name__)

base_dir = os.path.dirname(os.path.dirname(__file__))

# Key storage paths
KEY_DIR = os.path.join(base_dir, 'keys')
PRIVATE_KEY_PATH = os.path.join(KEY_DIR, "private.pem")
PUBLIC_KEY_PATH = os.path.join(KEY_DIR, "public.pem")

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s:%(levelname)s:%(message)s",
    handlers=[logging.StreamHandler()],
)


# def get_role_based_ui():
#     role_id_get = None
#     if current_user.role == "admin":
#         role_id_get = current_app.config["SALEM_DASHBOARD_ID"]
#     elif current_user.role == 'salem':
#         role_id_get = current_app.config["SALEM_DASHBOARD_ID"]
#     elif current_user.role == 'regency':
#         role_id_get = current_app.config["REGENCY_DASHBOARD_ID"]
#     elif current_user.role == 'agarwal':
#         role_id_get = current_app.config["AGARWAL_DASHBOARD_ID"]
#     elif current_user.role == 'east_point':
#         role_id_get = current_app.config["EP_DASHBOARD_ID"]
#     elif current_user.role == 'cmh':
#         role_id_get = current_app.config["CMH_DASHBOARD_ID"]
#     elif current_user.role == 'ovum_kalyan_nagar':
#         role_id_get = current_app.config["OVUM_KALYAN_NAGAR_DASHBOARD_ID"]
#     elif current_user.role == 'star':
#         role_id_get = current_app.config["STAR_DASHBOARD_ID"]
#     elif current_user.role == 'sparsh':
#         role_id_get = current_app.config["SPARSH_DASHBOARD_ID"]
#     elif current_user.role == 'care':
#         role_id_get = current_app.config["CARE_DASHBOARD_ID"]
#
#     return role_id_get

def get_role_based_ui():
    role_id_get = None
    if current_user.role == "admin":
        role_id_get = current_app.config["SALEM_DASHBOARD_ID"]
    elif current_user.role == 'salem':
        role_id_get = current_app.config["SALEM_DASHBOARD_ID"]
    elif current_user.role == 'regency':
        role_id_get = current_app.config["REGENCY_DASHBOARD_ID"]
    elif current_user.role == 'agarwal':
        role_id_get = current_app.config["AGARWAL_DASHBOARD_ID"]
    elif current_user.role == 'east_point':
        role_id_get = current_app.config["EP_DASHBOARD_ID"]
    elif current_user.role == 'cmh':
        role_id_get = current_app.config["CMH_DASHBOARD_ID"]
    elif current_user.role == 'ovum_kalyan_nagar':
        role_id_get = current_app.config["OVUM_KALYAN_NAGAR_DASHBOARD_ID"]
    elif current_user.role == 'star':
        role_id_get = current_app.config["STAR_DASHBOARD_ID"]
    elif current_user.role == 'sparsh':
        role_id_get = current_app.config["SPARSH_DASHBOARD_ID"]
    elif current_user.role == 'care':
        role_id_get = current_app.config["CARE_DASHBOARD_ID"]
    elif current_user.role == 'salem dialysis':
        role_id_get = current_app.config["SALEM_DIALYSIS_DASHBOARD_ID"]
    elif current_user.role == 'class':
        role_id_get = current_app.config["CLASS_DASHBOARD_ID"]
    elif current_user.role == 'dcdc':
        role_id_get = current_app.config["DCDC_DIALYSIS_DASHBOARD_ID"]
    elif current_user.role == 'dcdc_all':
        role_id_get = current_app.config["DCDC_ALL_DIALYSIS_DASHBOARD_ID"]
    elif current_user.role == 'aig':
        role_id_get = current_app.config["AIG_DASHBOARD_ID"]
    elif current_user.role == 'ovum_all':
        role_id_get = current_app.config["OVUM_ALL_DASHBOARD_ID"]
    elif current_user.role == 'nephroplus':
        role_id_get = current_app.config["NEPHROPLUS_DASHBOARD_ID"]
    return role_id_get

@main.app_errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403


@main.route('/')
def index():
    # print(current_app.config['API_TOKEN'])
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('main.dashboard'))
        else:
            return redirect(url_for('main.dashboard'))
    else:
        return redirect(url_for('auth.login'))


# @main.route('/dashboard')
# # @role_required('admin')
# @login_required
# def dashboard():
#     return render_template('dashboard.html')



@main.route("/dashboard")
@login_required
def dashboard():
    """
    Default route to load dashboard.html (loads the Embedded SDK).
    """

    auth_type = request.args.get("auth_type", "pem")

    selected_dashboard_id = request.args.get("dashboardId")

    print("Dashboard id", selected_dashboard_id)

    if selected_dashboard_id and current_user.is_authenticated and current_user.role == 'admin':
        session["dashboardId"] = selected_dashboard_id
    else:
        # fallback if not set yet
        # selected_dashboard_id = session.get("dashboardId", get_role_based_ui())
        selected_dashboard_id = get_role_based_ui()

    if auth_type == "pem":
        if not os.path.exists(PRIVATE_KEY_PATH) or not os.path.exists(PUBLIC_KEY_PATH):
            raise FileNotFoundError("PEM key files not found.")
        if current_app.config["KEY_ID"] is None:
            raise KeyError("Key ID not defined in environment variables.")
        return render_template(
            "dashboard.html",
            dashboardId=selected_dashboard_id,
            supersetDomain=current_app.config["SUPERSET_DOMAIN"],
            authType=auth_type,
        )

    # Default to API key auth
    return render_template(
        "dashboard.html",
        dashboardId=selected_dashboard_id,
        supersetDomain=current_app.config["SUPERSET_DOMAIN"],
        authType="api",
    )


@main.route("/guest-token", methods=["GET"])
@login_required
def guest_token_generator():
    """
    Route used by frontend to retrieve a Guest Token.
    """
    try:
        jwt_token = authenticate_with_preset()
        guest_token = jsonify(fetch_guest_token(jwt_token))
        return guest_token, 200
    except requests.exceptions.HTTPError as error:
        return jsonify({"error": str(error)}), 500


def authenticate_with_preset():
    """
    Authenticate with the Preset API to generate a JWT token.
    """
    url = current_app.config["PRESET_BASE_URL"] / "v1/auth/"
    payload = {"name": current_app.config["API_TOKEN"], "secret": current_app.config["API_SECRET"]}
    headers = {"Content-Type": "application/json", "Accept": "application/json"}

    try:
        response = requests.post(
            url,
            headers=headers,
            json=payload,
            timeout=7,
        )
        response.raise_for_status()
        return response.json()["payload"]["access_token"]
    except requests.exceptions.HTTPError as http_error:
        error_msg = http_error.response.text
        logging.error(
            "\nERROR: Unable to generate a JWT token.\nError details: %s",
            error_msg,
        )
        raise requests.exceptions.HTTPError(
            "Unable to generate a JWT token. "
            "Please make sure your API key is enabled.",
        )


def fetch_guest_token(jwt_key):
    """
    Fetch and return a Guest Token for the embedded dashboard.
    """

    selected_dashboard_id = session.get("dashboardId", get_role_based_ui())
    if selected_dashboard_id and current_user.is_authenticated and current_user.role == 'admin':
        session["dashboardId"] = selected_dashboard_id
    else:
        selected_dashboard_id = get_role_based_ui()

    url = (
        current_app.config["PRESET_BASE_URL"]
        / "v1/teams"
        / current_app.config["PRESET_TEAM"]
        / "workspaces"
        / current_app.config["WORKSPACE_SLUG"]
        / "guest-token/"
    )
    payload = {
        "user": {"username": "test_user", "first_name": "test", "last_name": "user"},
        "resources": [{"type": "dashboard", "id": selected_dashboard_id}],
        "rls": [
            # Apply an RLS to a specific dataset
            # { "dataset": dataset_id, "clause": "column = 'filter'" },
            # Apply an RLS to all datasets
            # { "clause": "column = 'filter'" },
        ],
    }

    headers = {
        "Authorization": f"Bearer {jwt_key}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    try:
        response = requests.post(
            url,
            headers=headers,
            json=payload,
            timeout=7,
        )
        response.raise_for_status()
        return response.json()["payload"]["token"]
    except requests.exceptions.HTTPError as http_error:
        error_msg = http_error.response.text
        logging.error(
            "\nERROR: Unable to fetch a Guest Token.\nError details: %s",
            error_msg,
        )
        raise requests.exceptions.HTTPError(
            "Unable to generate a Guest token. "
            "Please make sure the API key has admin access and the payload is correct.",
        )


@main.route("/pem-key", methods=["GET"])
@login_required
def get_guest_token_using_pem_key():
    """
    Encode and return a Guest Token for the embedded dashboard.
    """

    selected_dashboard_id = session.get("dashboardId", get_role_based_ui())
    if selected_dashboard_id and current_user.is_authenticated and current_user.role == 'admin':
        session["dashboardId"] = selected_dashboard_id
    else:
        selected_dashboard_id = get_role_based_ui()

    with open(PRIVATE_KEY_PATH, "r", encoding="utf-8") as file:
        private_key = file.read()

    # Payload to encode
    payload = {
        "user": {"username": "test_user", "first_name": "test", "last_name": "user"},
        "resources": [{"type": "dashboard", "id": selected_dashboard_id}],
        "rls_rules": [
            # Apply an RLS to a specific dataset
            # { "dataset": dataset_id, "clause": "column = 'filter'" },
            # Apply an RLS to all datasets
            # { "clause": "column = 'filter'" },
        ],
        "type": "guest",
        "aud": current_app.config["WORKSPACE_SLUG"],
    }

    encoded_jwt = jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers={"kid": current_app.config["KEY_ID"]},
    )
    return json.dumps(encoded_jwt)


