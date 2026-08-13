import os
import re
import secrets
import logging
from datetime import datetime, timezone
from functools import wraps

import requests
from flask import Flask, request, jsonify, g
from flask_cors import CORS


# ============================================================
# CONFIGURATION
# ============================================================

app = Flask(__name__)

# ------------------------------------------------------------
# Logging
# ------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

logger = logging.getLogger(__name__)


# ------------------------------------------------------------
# CORS
#
# Set FRONTEND_URL on Render to your actual frontend URL.
#
# Example:
# FRONTEND_URL=https://yourfrontend.com
#
# During development you can use:
# FRONTEND_URL=http://localhost:3000
# ------------------------------------------------------------

frontend_url = os.getenv("FRONTEND_URL", "*")

CORS(
    app,
    resources={
        r"/api/*": {
            "origins": frontend_url
        }
    },
    supports_credentials=True
)


# ------------------------------------------------------------
# Required environment variables
# ------------------------------------------------------------

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")


def validate_environment():
    """
    Make sure required environment variables exist.
    """

    missing = []

    if not SUPABASE_URL:
        missing.append("SUPABASE_URL")

    if not SUPABASE_ANON_KEY:
        missing.append("SUPABASE_ANON_KEY")

    if not SUPABASE_SERVICE_ROLE_KEY:
        missing.append("SUPABASE_SERVICE_ROLE_KEY")

    if missing:
        raise RuntimeError(
            "Missing required environment variables: "
            + ", ".join(missing)
        )


validate_environment()


# Remove trailing slash if somebody supplied one.
SUPABASE_URL = SUPABASE_URL.rstrip("/")


# ============================================================
# SUPABASE ENDPOINTS
# ============================================================

SUPABASE_AUTH_URL = f"{SUPABASE_URL}/auth/v1"

SUPABASE_REST_URL = f"{SUPABASE_URL}/rest/v1"


# ============================================================
# HTTP SESSION
# ============================================================

http = requests.Session()

http.headers.update({
    "Accept": "application/json"
})


# ============================================================
# CONSTANTS
# ============================================================

MAX_NAME_LENGTH = 100
MAX_USERNAME_LENGTH = 50
MAX_EMAIL_LENGTH = 320
MIN_PASSWORD_LENGTH = 8


# ============================================================
# GENERAL HELPERS
# ============================================================

def json_error(message, status_code=400, **extra):
    """
    Standard JSON error response.
    """

    payload = {
        "success": False,
        "error": message
    }

    payload.update(extra)

    return jsonify(payload), status_code


def json_success(data=None, status_code=200):
    """
    Standard JSON success response.
    """

    payload = {
        "success": True
    }

    if data:
        payload.update(data)

    return jsonify(payload), status_code


def get_json_body():
    """
    Safely obtain JSON request body.
    """

    if not request.is_json:
        return None

    try:
        return request.get_json(silent=True)
    except Exception:
        return None


def clean_string(value, max_length=None):
    """
    Convert a value to a cleaned string.
    """

    if value is None:
        return ""

    value = str(value).strip()

    if max_length:
        value = value[:max_length]

    return value


def validate_email(email):
    """
    Basic email validation.
    """

    if not email:
        return False

    if len(email) > MAX_EMAIL_LENGTH:
        return False

    pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"

    return re.match(pattern, email) is not None


def validate_password(password):
    """
    Basic password validation.

    Supabase Auth remains responsible for the actual password
    authentication and password hashing.
    """

    if not password:
        return False

    if len(password) < MIN_PASSWORD_LENGTH:
        return False

    return True


def validate_username(username):
    """
    Username rules:
    - 3 to 50 characters
    - letters
    - numbers
    - underscore
    - period
    """

    if not username:
        return False

    if len(username) < 3:
        return False

    if len(username) > MAX_USERNAME_LENGTH:
        return False

    return re.match(
        r"^[a-zA-Z0-9_.]+$",
        username
    ) is not None


def normalize_email(email):
    """
    Normalize email before sending to Supabase.
    """

    return email.strip().lower()


def normalize_username(username):
    """
    Normalize username.
    """

    return username.strip().lower()


# ============================================================
# SUPABASE REQUEST HELPERS
# ============================================================

def supabase_auth_headers(api_key=None, access_token=None):
    """
    Headers for Supabase Auth API.
    """

    if api_key is None:
        api_key = SUPABASE_ANON_KEY

    headers = {
        "apikey": api_key,
        "Content-Type": "application/json"
    }

    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"

    return headers


def supabase_database_headers(use_service_role=True, access_token=None):
    """
    Headers for Supabase PostgREST.

    The service role key is used only server-side.
    """

    key = (
        SUPABASE_SERVICE_ROLE_KEY
        if use_service_role
        else SUPABASE_ANON_KEY
    )

    headers = {
        "apikey": key,
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
        "Prefer": "return=representation"
    }

    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"

    return headers


def extract_supabase_error(response):
    """
    Extract a useful error message from Supabase.
    """

    try:
        data = response.json()
    except Exception:
        return "Supabase request failed."

    if isinstance(data, dict):

        # Common Supabase Auth errors
        for key in (
            "msg",
            "message",
            "error_description",
            "error"
        ):
            value = data.get(key)

            if value:
                return str(value)

    return "Supabase request failed."


# ============================================================
# AUTHENTICATION FUNCTIONS
# ============================================================

def supabase_signup(email, password, user_metadata):
    """
    Create a Supabase Auth user.
    """

    url = f"{SUPABASE_AUTH_URL}/signup"

    payload = {
        "email": email,
        "password": password,
        "data": user_metadata
    }

    try:
        response = http.post(
            url,
            headers=supabase_auth_headers(),
            json=payload,
            timeout=15
        )
    except requests.RequestException as exc:
        logger.error("Supabase signup connection error: %s", exc)

        return None, "Unable to connect to authentication service."

    if response.status_code not in (200, 201):

        error = extract_supabase_error(response)

        logger.warning(
            "Supabase signup failed: %s",
            error
        )

        return None, error

    try:
        return response.json(), None
    except Exception:
        return None, "Invalid response from authentication service."


def supabase_login(email, password):
    """
    Authenticate a user with Supabase Auth.
    """

    url = f"{SUPABASE_AUTH_URL}/token"

    params = {
        "grant_type": "password"
    }

    payload = {
        "email": email,
        "password": password
    }

    try:
        response = http.post(
            url,
            params=params,
            headers=supabase_auth_headers(),
            json=payload,
            timeout=15
        )

    except requests.RequestException as exc:
        logger.error("Supabase login connection error: %s", exc)

        return None, "Unable to connect to authentication service."

    if response.status_code != 200:

        error = extract_supabase_error(response)

        logger.warning(
            "Supabase login failed: %s",
            error
        )

        return None, error

    try:
        return response.json(), None
    except Exception:
        return None, "Invalid response from authentication service."


def supabase_get_user(access_token):
    """
    Verify the access token and retrieve the authenticated user.
    """

    url = f"{SUPABASE_AUTH_URL}/user"

    try:
        response = http.get(
            url,
            headers=supabase_auth_headers(
                access_token=access_token
            ),
            timeout=15
        )

    except requests.RequestException as exc:
        logger.error("Supabase user verification error: %s", exc)

        return None, "Unable to verify authentication."

    if response.status_code != 200:
        return None, extract_supabase_error(response)

    try:
        return response.json(), None
    except Exception:
        return None, "Invalid authentication response."


def supabase_logout(access_token):
    """
    Invalidate the user's current Supabase session.
    """

    url = f"{SUPABASE_AUTH_URL}/logout"

    try:
        response = http.post(
            url,
            headers=supabase_auth_headers(
                access_token=access_token
            ),
            timeout=15
        )

    except requests.RequestException as exc:
        logger.error("Supabase logout error: %s", exc)

        return False, "Unable to contact authentication service."

    if response.status_code not in (200, 204):
        return False, extract_supabase_error(response)

    return True, None


# ============================================================
# DATABASE FUNCTIONS
# ============================================================

def create_profile(user_id, email, full_name, username):
    """
    Create the application's profile row.

    IMPORTANT:
    The database should contain a table called `profiles`.

    Recommended columns:

        id          uuid primary key
        email       text
        full_name   text
        username    text unique
        created_at  timestamptz
        updated_at  timestamptz
    """

    url = f"{SUPABASE_REST_URL}/profiles"

    payload = {
        "id": user_id,
        "email": email,
        "full_name": full_name,
        "username": username
    }

    try:
        response = http.post(
            url,
            headers=supabase_database_headers(
                use_service_role=True
            ),
            json=payload,
            timeout=15
        )

    except requests.RequestException as exc:
        logger.error("Profile database connection error: %s", exc)

        return None, "Unable to save user profile."

    if response.status_code not in (200, 201):

        error = extract_supabase_error(response)

        logger.error(
            "Failed to create profile: %s",
            error
        )

        return None, error

    try:
        data = response.json()

        if isinstance(data, list) and data:
            return data[0], None

        return data, None

    except Exception:
        return None, "Invalid database response."


def get_profile(user_id):
    """
    Retrieve the user's profile.
    """

    url = f"{SUPABASE_REST_URL}/profiles"

    params = {
        "id": f"eq.{user_id}",
        "select": "id,email,full_name,username,created_at,updated_at"
    }

    try:
        response = http.get(
            url,
            params=params,
            headers=supabase_database_headers(
                use_service_role=True
            ),
            timeout=15
        )

    except requests.RequestException as exc:
        logger.error("Profile lookup error: %s", exc)

        return None, "Unable to retrieve profile."

    if response.status_code != 200:
        return None, extract_supabase_error(response)

    try:
        data = response.json()

        if not data:
            return None, None

        return data[0], None

    except Exception:
        return None, "Invalid database response."


def check_username_exists(username):
    """
    Check whether username already exists.
    """

    url = f"{SUPABASE_REST_URL}/profiles"

    params = {
        "username": f"eq.{username}",
        "select": "id"
    }

    try:
        response = http.get(
            url,
            params=params,
            headers=supabase_database_headers(
                use_service_role=True
            ),
            timeout=15
        )

    except requests.RequestException as exc:
        logger.error("Username lookup error: %s", exc)

        return None, "Unable to check username."

    if response.status_code != 200:
        return None, extract_supabase_error(response)

    try:
        data = response.json()

        return len(data) > 0, None

    except Exception:
        return None, "Invalid database response."


def delete_profile(user_id):
    """
    Delete profile if account creation succeeded but
    profile creation failed.

    This helps prevent partially-created accounts.
    """

    url = f"{SUPABASE_REST_URL}/profiles"

    params = {
        "id": f"eq.{user_id}"
    }

    try:
        response = http.delete(
            url,
            params=params,
            headers=supabase_database_headers(
                use_service_role=True
            ),
            timeout=15
        )

        return response.status_code in (200, 204)

    except requests.RequestException:
        return False


# ============================================================
# AUTH DECORATOR
# ============================================================

def require_authentication(function):
    """
    Protect an endpoint using a Supabase access token.

    Frontend sends:

        Authorization: Bearer <access_token>
    """

    @wraps(function)
    def decorated(*args, **kwargs):

        authorization = request.headers.get("Authorization", "")

        if not authorization:
            return json_error(
                "Authentication token is required.",
                401
            )

        if not authorization.startswith("Bearer "):
            return json_error(
                "Invalid authorization header.",
                401
            )

        access_token = authorization[7:].strip()

        if not access_token:
            return json_error(
                "Authentication token is required.",
                401
            )

        user, error = supabase_get_user(access_token)

        if error or not user:

            return json_error(
                "Invalid or expired authentication token.",
                401
            )

        # Store authenticated user for the route.
        g.user = user
        g.access_token = access_token

        return function(*args, **kwargs)

    return decorated


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/", methods=["GET"])
def home():
    """
    Basic health check.
    """

    return jsonify({
        "success": True,
        "service": "Authentication API",
        "status": "running"
    })


@app.route("/api/health", methods=["GET"])
def health():
    """
    API health endpoint.
    """

    return jsonify({
        "success": True,
        "status": "healthy"
    })


# ============================================================
# SIGNUP
# ============================================================

@app.route("/api/auth/signup", methods=["POST"])
def signup():

    data = get_json_body()

    if not data:
        return json_error(
            "Request body must be valid JSON.",
            400
        )

    email = normalize_email(
        clean_string(data.get("email"))
    )

    password = data.get("password", "")

    full_name = clean_string(
        data.get("full_name"),
        MAX_NAME_LENGTH
    )

    username = normalize_username(
        clean_string(
            data.get("username"),
            MAX_USERNAME_LENGTH
        )
    )

    # --------------------------------------------------------
    # Validate email
    # --------------------------------------------------------

    if not validate_email(email):
        return json_error(
            "Please provide a valid email address.",
            400
        )

    # --------------------------------------------------------
    # Validate password
    # --------------------------------------------------------

    if not validate_password(password):
        return json_error(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters.",
            400
        )

    # --------------------------------------------------------
    # Validate full name
    # --------------------------------------------------------

    if not full_name:
        return json_error(
            "Full name is required.",
            400
        )

    # --------------------------------------------------------
    # Validate username
    # --------------------------------------------------------

    if not validate_username(username):
        return json_error(
            "Username must be 3-50 characters and contain only "
            "letters, numbers, underscores or periods.",
            400
        )

    # --------------------------------------------------------
    # Check username availability
    # --------------------------------------------------------

    username_exists, username_error = check_username_exists(
        username
    )

    if username_error:
        return json_error(
            "Unable to verify username availability.",
            500
        )

    if username_exists:
        return json_error(
            "Username is already taken.",
            409
        )

    # --------------------------------------------------------
    # Create Supabase Auth user
    # --------------------------------------------------------

    user_metadata = {
        "full_name": full_name,
        "username": username
    }

    auth_data, auth_error = supabase_signup(
        email,
        password,
        user_metadata
    )

    if auth_error:

        # Avoid leaking unnecessary authentication details.
        lower_error = auth_error.lower()

        if (
            "already registered" in lower_error
            or "already exists" in lower_error
            or "already been registered" in lower_error
        ):
            return json_error(
                "An account with this email already exists.",
                409
            )

        return json_error(
            auth_error,
            400
        )

    # --------------------------------------------------------
    # Extract Supabase user
    # --------------------------------------------------------

    user = auth_data.get("user")

    if not user:
        return json_error(
            "Account creation failed.",
            500
        )

    user_id = user.get("id")

    if not user_id:
        return json_error(
            "Account creation returned no user ID.",
            500
        )

    # --------------------------------------------------------
    # Create profile in database
    # --------------------------------------------------------

    profile, profile_error = create_profile(
        user_id=user_id,
        email=email,
        full_name=full_name,
        username=username
    )

    if profile_error:

        logger.error(
            "Profile creation failed for user %s: %s",
            user_id,
            profile_error
        )

        # Best-effort cleanup of profile.
        delete_profile(user_id)

        return json_error(
            "Account was created but user profile could not be saved. "
            "Please contact support.",
            500
        )

    # --------------------------------------------------------
    # Determine whether Supabase returned a session.
    #
    # If email confirmation is disabled, Supabase normally
    # returns access/refresh tokens immediately.
    #
    # If email confirmation is enabled, session may be null.
    # --------------------------------------------------------

    session = auth_data.get("session")

    response_data = {
        "message": "Account created successfully.",
        "user": {
            "id": user_id,
            "email": email,
            "full_name": full_name,
            "username": username
        }
    }

    if session:

        response_data["session"] = {
            "access_token": session.get("access_token"),
            "refresh_token": session.get("refresh_token"),
            "expires_in": session.get("expires_in"),
            "expires_at": session.get("expires_at"),
            "token_type": session.get("token_type")
        }

        response_data["message"] = (
            "Account created and authenticated successfully."
        )

    else:

        response_data["message"] = (
            "Account created successfully. "
            "Please verify your email before logging in."
        )

    logger.info(
        "New user registered: %s",
        user_id
    )

    return json_success(
        response_data,
        201
    )


# ============================================================
# LOGIN
# ============================================================

@app.route("/api/auth/login", methods=["POST"])
def login():

    data = get_json_body()

    if not data:
        return json_error(
            "Request body must be valid JSON.",
            400
        )

    email = normalize_email(
        clean_string(data.get("email"))
    )

    password = data.get("password", "")

    if not validate_email(email):
        return json_error(
            "Please provide a valid email address.",
            400
        )

    if not password:
        return json_error(
            "Password is required.",
            400
        )

    # --------------------------------------------------------
    # Authenticate against Supabase Auth
    # --------------------------------------------------------

    auth_data, auth_error = supabase_login(
        email,
        password
    )

    if auth_error:

        return json_error(
            "Invalid email or password.",
            401
        )

    user = auth_data.get("user")
    session = auth_data.get("session")

    if not user or not session:
        return json_error(
            "Login was unsuccessful.",
            401
        )

    user_id = user.get("id")

    # --------------------------------------------------------
    # Retrieve application profile
    # --------------------------------------------------------

    profile, profile_error = get_profile(user_id)

    if profile_error:
        return json_error(
            "Unable to retrieve user profile.",
            500
        )

    # --------------------------------------------------------
    # Return session to frontend
    # --------------------------------------------------------

    response_data = {
        "message": "Login successful.",
        "user": {
            "id": user.get("id"),
            "email": user.get("email"),
            "full_name": (
                profile.get("full_name")
                if profile
                else user.get("user_metadata", {}).get("full_name")
            ),
            "username": (
                profile.get("username")
                if profile
                else user.get("user_metadata", {}).get("username")
            )
        },
        "session": {
            "access_token": session.get("access_token"),
            "refresh_token": session.get("refresh_token"),
            "expires_in": session.get("expires_in"),
            "expires_at": session.get("expires_at"),
            "token_type": session.get("token_type")
        }
    }

    logger.info(
        "Successful login for user: %s",
        user_id
    )

    return json_success(
        response_data,
        200
    )


# ============================================================
# CURRENT USER
# ============================================================

@app.route("/api/auth/me", methods=["GET"])
@require_authentication
def current_user():

    user = g.user

    user_id = user.get("id")

    profile, profile_error = get_profile(user_id)

    if profile_error:
        return json_error(
            "Unable to retrieve profile.",
            500
        )

    return json_success({
        "user": {
            "id": user.get("id"),
            "email": user.get("email"),
            "full_name": (
                profile.get("full_name")
                if profile
                else user.get("user_metadata", {}).get("full_name")
            ),
            "username": (
                profile.get("username")
                if profile
                else user.get("user_metadata", {}).get("username")
            ),
            "created_at": user.get("created_at")
        },
        "profile": profile
    })


# ============================================================
# LOGOUT
# ============================================================

@app.route("/api/auth/logout", methods=["POST"])
@require_authentication
def logout():

    access_token = g.access_token

    success, error = supabase_logout(
        access_token
    )

    if not success:
        return json_error(
            "Logout failed.",
            500
        )

    return json_success({
        "message": "Logged out successfully."
    })


# ============================================================
# FORGOT PASSWORD
# ============================================================

@app.route("/api/auth/forgot-password", methods=["POST"])
def forgot_password():

    data = get_json_body()

    if not data:
        return json_error(
            "Request body must be valid JSON.",
            400
        )

    email = normalize_email(
        clean_string(data.get("email"))
    )

    if not validate_email(email):
        return json_error(
            "Please provide a valid email address.",
            400
        )

    # --------------------------------------------------------
    # Supabase password recovery endpoint
    # --------------------------------------------------------

    url = f"{SUPABASE_AUTH_URL}/recover"

    payload = {
        "email": email
    }

    try:

        response = http.post(
            url,
            headers=supabase_auth_headers(),
            json=payload,
            timeout=15
        )

    except requests.RequestException as exc:

        logger.error(
            "Password recovery connection error: %s",
            exc
        )

        return json_error(
            "Unable to process password recovery.",
            500
        )

    if response.status_code not in (200, 201, 204):

        logger.warning(
            "Password recovery request failed: %s",
            extract_supabase_error(response)
        )

        # Don't reveal whether an email exists.
        return json_success({
            "message": (
                "If an account exists for this email, "
                "a password reset email will be sent."
            )
        })

    return json_success({
        "message": (
            "If an account exists for this email, "
            "a password reset email will be sent."
        )
    })


# ============================================================
# REFRESH SESSION
# ============================================================

@app.route("/api/auth/refresh", methods=["POST"])
def refresh_session():

    data = get_json_body()

    if not data:
        return json_error(
            "Request body must be valid JSON.",
            400
        )

    refresh_token = clean_string(
        data.get("refresh_token")
    )

    if not refresh_token:
        return json_error(
            "Refresh token is required.",
            400
        )

    url = f"{SUPABASE_AUTH_URL}/token"

    params = {
        "grant_type": "refresh_token"
    }

    payload = {
        "refresh_token": refresh_token
    }

    try:

        response = http.post(
            url,
            params=params,
            headers=supabase_auth_headers(),
            json=payload,
            timeout=15
        )

    except requests.RequestException as exc:

        logger.error(
            "Token refresh connection error: %s",
            exc
        )

        return json_error(
            "Unable to refresh authentication session.",
            500
        )

    if response.status_code != 200:

        return json_error(
            "Invalid or expired refresh token.",
            401
        )

    try:

        session = response.json()

    except Exception:

        return json_error(
            "Invalid response from authentication service.",
            500
        )

    return json_success({
        "message": "Session refreshed successfully.",
        "session": {
            "access_token": session.get("access_token"),
            "refresh_token": session.get("refresh_token"),
            "expires_in": session.get("expires_in"),
            "expires_at": session.get("expires_at"),
            "token_type": session.get("token_type")
        }
    })


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(400)
def bad_request(error):

    return json_error(
        "Bad request.",
        400
    )


@app.errorhandler(404)
def not_found(error):

    return json_error(
        "Endpoint not found.",
        404
    )


@app.errorhandler(405)
def method_not_allowed(error):

    return json_error(
        "HTTP method not allowed.",
        405
    )


@app.errorhandler(500)
def internal_server_error(error):

    logger.exception(
        "Unhandled server error: %s",
        error
    )

    return json_error(
        "Internal server error.",
        500
    )


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    port = int(
        os.getenv("PORT", "5000")
    )

    host = "0.0.0.0"

    logger.info(
        "Starting authentication API on %s:%s",
        host,
        port
    )

    app.run(
        host=host,
        port=port,
        debug=False
    )
