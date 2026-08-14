import os
import re
import logging
from functools import wraps

import requests
from flask import Flask, request, jsonify, g
from flask_cors import CORS

app = Flask(__name__)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

logger = logging.getLogger(__name__)

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
FRONTEND_URL = os.getenv("FRONTEND_URL", "").strip().rstrip("/")

def validate_environment():
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

SUPABASE_URL = SUPABASE_URL.rstrip("/")
SUPABASE_AUTH_URL = f"{SUPABASE_URL}/auth/v1"
SUPABASE_REST_URL = f"{SUPABASE_URL}/rest/v1"

CORS(
    app,
    resources={
        r"/api/*": {
            "origins": (
                [FRONTEND_URL]
                if FRONTEND_URL
                else "*"
            )
        }
    },
    supports_credentials=True
)

http = requests.Session()

http.headers.update({
    "Accept": "application/json"
})

MAX_NAME_LENGTH = 100
MAX_USERNAME_LENGTH = 50
MAX_EMAIL_LENGTH = 320
MIN_PASSWORD_LENGTH = 8

def json_error(message, status_code=400, **extra):
    payload = {
        "success": False,
        "error": message
    }
    payload.update(extra)
    return jsonify(payload), status_code

def json_success(data=None, status_code=200):
    payload = {
        "success": True
    }

    if data:
        payload.update(data)

    return jsonify(payload), status_code

def get_json_body():
    if not request.is_json:
        return None

    try:
        return request.get_json(silent=True)
    except Exception:
        return None

def clean_string(value, max_length=None):
    if value is None:
        return ""

    value = str(value).strip()

    if max_length:
        value = value[:max_length]

    return value

def validate_email(email):
    if not email:
        return False

    if len(email) > MAX_EMAIL_LENGTH:
        return False

    return re.match(
        r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
        email
    ) is not None

def validate_password(password):
    if not password:
        return False

    return len(password) >= MIN_PASSWORD_LENGTH

def validate_username(username):
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
    return email.strip().lower()

def normalize_username(username):
    return username.strip().lower()

def supabase_auth_headers(api_key=None, access_token=None):
    if api_key is None:
        api_key = SUPABASE_ANON_KEY

    headers = {
        "apikey": api_key,
        "Content-Type": "application/json"
    }

    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"

    return headers

def supabase_service_headers():
    return {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "Content-Type": "application/json"
    }

def supabase_database_headers():
    return {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=representation"
    }

def extract_supabase_error(response):
    try:
        data = response.json()
    except Exception:
        return f"Supabase request failed with HTTP {response.status_code}."

    if isinstance(data, dict):
        for key in (
            "msg",
            "message",
            "error_description",
            "error",
            "error_code"
        ):
            value = data.get(key)

            if value:
                return str(value)

    return f"Supabase request failed with HTTP {response.status_code}."

def extract_session(data):
    """
    Normalize Supabase Auth responses.

    Supabase Auth REST responses return access_token,
    refresh_token, expires_in, expires_at and token_type
    at the top level.

    This function converts those fields into the session
    structure expected by our API.
    """

    if not isinstance(data, dict):
        return None

    existing_session = data.get("session")

    if isinstance(existing_session, dict):
        if existing_session.get("access_token"):
            return {
                "access_token": existing_session.get("access_token"),
                "refresh_token": existing_session.get("refresh_token"),
                "expires_in": existing_session.get("expires_in"),
                "expires_at": existing_session.get("expires_at"),
                "token_type": existing_session.get("token_type")
            }

    access_token = data.get("access_token")

    if not access_token:
        return None

    return {
        "access_token": access_token,
        "refresh_token": data.get("refresh_token"),
        "expires_in": data.get("expires_in"),
        "expires_at": data.get("expires_at"),
        "token_type": data.get("token_type")
    }

def supabase_signup(email, password, user_metadata):
    url = f"{SUPABASE_AUTH_URL}/signup"

    payload = {
        "email": email,
        "password": password,
        "data": user_metadata
    }

    if FRONTEND_URL:
        payload["redirect_to"] = FRONTEND_URL

    try:
        response = http.post(
            url,
            headers=supabase_auth_headers(),
            json=payload,
            timeout=20
        )
    except requests.RequestException as exc:
        logger.error(
            "SUPABASE SIGNUP CONNECTION ERROR | error=%s",
            exc
        )
        return None, "Unable to connect to authentication service."

    if response.status_code not in (200, 201):
        error = extract_supabase_error(response)

        logger.warning(
            "SUPABASE SIGNUP FAILED | status=%s | error=%s",
            response.status_code,
            error
        )

        return None, error

    try:
        data = response.json()
    except Exception:
        logger.error(
            "SUPABASE SIGNUP INVALID JSON | status=%s",
            response.status_code
        )
        return None, "Invalid response from authentication service."

    return data, None

def supabase_login(email, password):
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
            timeout=20
        )
    except requests.RequestException as exc:
        logger.error(
            "SUPABASE LOGIN CONNECTION ERROR | error=%s",
            exc
        )
        return None, "Unable to connect to authentication service."

    if response.status_code != 200:
        error = extract_supabase_error(response)

        logger.warning(
            "SUPABASE LOGIN REJECTED | status=%s | error=%s",
            response.status_code,
            error
        )

        return None, error

    try:
        data = response.json()
    except Exception:
        logger.error(
            "SUPABASE LOGIN INVALID JSON | status=%s",
            response.status_code
        )
        return None, "Invalid response from authentication service."

    session = extract_session(data)

    if session:
        data["session"] = session

    logger.info(
        "SUPABASE LOGIN SUCCESS | email=%s | user_id=%s | session=%s",
        email,
        data.get("user", {}).get("id"),
        bool(session)
    )

    return data, None

def supabase_get_user(access_token):
    url = f"{SUPABASE_AUTH_URL}/user"

    try:
        response = http.get(
            url,
            headers=supabase_auth_headers(
                access_token=access_token
            ),
            timeout=20
        )
    except requests.RequestException as exc:
        logger.error(
            "SUPABASE USER VERIFICATION ERROR | error=%s",
            exc
        )
        return None, "Unable to verify authentication."

    if response.status_code != 200:
        error = extract_supabase_error(response)

        logger.warning(
            "SUPABASE USER VERIFICATION FAILED | status=%s | error=%s",
            response.status_code,
            error
        )

        return None, error

    try:
        return response.json(), None
    except Exception:
        return None, "Invalid authentication response."

def supabase_logout(access_token):
    url = f"{SUPABASE_AUTH_URL}/logout"

    try:
        response = http.post(
            url,
            headers=supabase_auth_headers(
                access_token=access_token
            ),
            timeout=20
        )
    except requests.RequestException as exc:
        logger.error(
            "SUPABASE LOGOUT ERROR | error=%s",
            exc
        )
        return False, "Unable to contact authentication service."

    if response.status_code not in (200, 204):
        error = extract_supabase_error(response)

        logger.warning(
            "SUPABASE LOGOUT FAILED | status=%s | error=%s",
            response.status_code,
            error
        )

        return False, error

    return True, None

def delete_auth_user(user_id):
    """
    Permanently remove the Supabase Auth user.

    This is a server-side admin operation and therefore
    uses the service-role key.

    It is used only as rollback when profile creation fails.
    """

    url = f"{SUPABASE_AUTH_URL}/admin/users/{user_id}"

    try:
        response = http.delete(
            url,
            headers=supabase_service_headers(),
            timeout=20
        )
    except requests.RequestException as exc:
        logger.error(
            "AUTH USER ROLLBACK CONNECTION ERROR | user_id=%s | error=%s",
            user_id,
            exc
        )
        return False, "Unable to contact authentication service."

    if response.status_code not in (200, 204):
        error = extract_supabase_error(response)

        logger.error(
            "AUTH USER ROLLBACK FAILED | user_id=%s | status=%s | error=%s",
            user_id,
            response.status_code,
            error
        )

        return False, error

    logger.info(
        "AUTH USER ROLLBACK SUCCESSFUL | user_id=%s",
        user_id
    )

    return True, None

def create_profile(user_id, email, full_name, username):
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
            headers=supabase_database_headers(),
            json=payload,
            timeout=20
        )
    except requests.RequestException as exc:
        logger.error(
            "PROFILE DATABASE CONNECTION ERROR | user_id=%s | error=%s",
            user_id,
            exc
        )
        return None, "Unable to save user profile."

    if response.status_code not in (200, 201):
        error = extract_supabase_error(response)

        logger.error(
            "PROFILE CREATION FAILED | user_id=%s | status=%s | error=%s",
            user_id,
            response.status_code,
            error
        )

        return None, error

    try:
        data = response.json()
    except Exception:
        logger.error(
            "PROFILE CREATION INVALID JSON | user_id=%s",
            user_id
        )
        return None, "Invalid database response."

    if isinstance(data, list):
        if not data:
            return None, "Profile was not returned after creation."
        return data[0], None

    if isinstance(data, dict):
        return data, None

    return None, "Invalid database response."

def get_profile(user_id):
    url = f"{SUPABASE_REST_URL}/profiles"

    params = {
        "id": f"eq.{user_id}",
        "select": "id,email,full_name,username,created_at,updated_at"
    }

    try:
        response = http.get(
            url,
            params=params,
            headers=supabase_database_headers(),
            timeout=20
        )
    except requests.RequestException as exc:
        logger.error(
            "PROFILE LOOKUP CONNECTION ERROR | user_id=%s | error=%s",
            user_id,
            exc
        )
        return None, "Unable to retrieve profile."

    if response.status_code != 200:
        error = extract_supabase_error(response)

        logger.error(
            "PROFILE LOOKUP FAILED | user_id=%s | status=%s | error=%s",
            user_id,
            response.status_code,
            error
        )

        return None, error

    try:
        data = response.json()
    except Exception:
        return None, "Invalid database response."

    if not data:
        return None, None

    return data[0], None

def check_username_exists(username):
    url = f"{SUPABASE_REST_URL}/profiles"

    params = {
        "username": f"eq.{username}",
        "select": "id"
    }

    try:
        response = http.get(
            url,
            params=params,
            headers=supabase_database_headers(),
            timeout=20
        )
    except requests.RequestException as exc:
        logger.error(
            "USERNAME LOOKUP CONNECTION ERROR | username=%s | error=%s",
            username,
            exc
        )
        return None, "Unable to check username."

    if response.status_code != 200:
        error = extract_supabase_error(response)

        logger.error(
            "USERNAME LOOKUP FAILED | username=%s | status=%s | error=%s",
            username,
            response.status_code,
            error
        )

        return None, error

    try:
        data = response.json()
    except Exception:
        return None, "Invalid database response."

    return len(data) > 0, None

def require_authentication(function):
    @wraps(function)
    def decorated(*args, **kwargs):
        authorization = request.headers.get(
            "Authorization",
            ""
        )

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

        user, error = supabase_get_user(
            access_token
        )

        if error or not user:
            return json_error(
                "Invalid or expired authentication token.",
                401
            )

        g.user = user
        g.access_token = access_token

        return function(*args, **kwargs)

    return decorated

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "success": True,
        "service": "Authentication API",
        "status": "running"
    })

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "success": True,
        "status": "healthy"
    })

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

    if not validate_email(email):
        return json_error(
            "Please provide a valid email address.",
            400
        )

    if not validate_password(password):
        return json_error(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters.",
            400
        )

    if not full_name:
        return json_error(
            "Full name is required.",
            400
        )

    if not validate_username(username):
        return json_error(
            "Username must be 3-50 characters and contain only "
            "letters, numbers, underscores or periods.",
            400
        )

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
        lower_error = auth_error.lower()

        if (
            "already registered" in lower_error
            or "already exists" in lower_error
            or "already been registered" in lower_error
            or "user already registered" in lower_error
        ):
            return json_error(
                "An account with this email already exists.",
                409
            )

        return json_error(
            auth_error,
            400
        )

    if not auth_data:
        return json_error(
            "Account creation failed.",
            500
        )

    user = auth_data.get("user")

    if not user:
        logger.error(
            "SIGNUP FAILED | Supabase returned no user."
        )

        return json_error(
            "Account creation failed: Supabase returned no user.",
            500
        )

    user_id = user.get("id")

    if not user_id:
        logger.error(
            "SIGNUP FAILED | Supabase returned no user ID."
        )

        return json_error(
            "Account creation returned no user ID.",
            500
        )

    profile, profile_error = create_profile(
        user_id=user_id,
        email=email,
        full_name=full_name,
        username=username
    )

    if profile_error:
        logger.error(
            "PROFILE CREATION FAILED | user_id=%s | error=%s",
            user_id,
            profile_error
        )

        rollback_success, rollback_error = delete_auth_user(
            user_id
        )

        if not rollback_success:
            logger.critical(
                "CRITICAL SIGNUP ROLLBACK FAILURE | "
                "user_id=%s | profile_error=%s | rollback_error=%s",
                user_id,
                profile_error,
                rollback_error
            )

            return json_error(
                "Account creation could not be completed. "
                "Please contact support.",
                500
            )

        return json_error(
            "Account creation could not be completed. "
            "Please try again.",
            500
        )

    session = extract_session(auth_data)

    response_data = {
        "user": {
            "id": user_id,
            "email": email,
            "full_name": full_name,
            "username": username
        }
    }

    if session:
        response_data["message"] = (
            "Account created and authenticated successfully."
        )

        response_data["session"] = session
    else:
        response_data["message"] = (
            "Account created successfully. "
            "Please verify your email before logging in."
        )

    logger.info(
        "NEW USER REGISTERED | user_id=%s | email=%s | username=%s",
        user_id,
        email,
        username
    )

    return json_success(
        response_data,
        201
    )

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

    auth_data, auth_error = supabase_login(
        email,
        password
    )

    if auth_error:
        logger.warning(
            "SUPABASE LOGIN REJECTED | email=%s | error=%s",
            email,
            auth_error
        )

        return json_error(
            auth_error,
            401
        )

    if not auth_data:
        return json_error(
            "Login was unsuccessful.",
            401
        )

    user = auth_data.get("user")
    session = extract_session(auth_data)

    if not user:
        logger.error(
            "LOGIN FAILED | Supabase returned no user | email=%s",
            email
        )

        return json_error(
            "Login was unsuccessful. No authenticated user was returned.",
            401
        )

    if not session:
        logger.error(
            "LOGIN FAILED | no session returned | user_id=%s | email=%s",
            user.get("id"),
            email
        )

        return json_error(
            "Login was unsuccessful. No authentication session was returned.",
            401
        )

    user_id = user.get("id")

    if not user_id:
        return json_error(
            "Login was unsuccessful. No user ID was returned.",
            401
        )

    profile, profile_error = get_profile(
        user_id
    )

    if profile_error:
        logger.error(
            "PROFILE RETRIEVAL FAILED | user_id=%s | error=%s",
            user_id,
            profile_error
        )

        return json_error(
            "Authentication succeeded, but the user profile could not be retrieved.",
            500
        )

    if not profile:
        logger.error(
            "PROFILE NOT FOUND | user_id=%s | email=%s",
            user_id,
            email
        )

        return json_error(
            "Authentication succeeded, but the user profile was not found.",
            500
        )

    response_data = {
        "message": "Login successful.",
        "user": {
            "id": user.get("id"),
            "email": user.get("email"),
            "full_name": profile.get("full_name"),
            "username": profile.get("username")
        },
        "session": session
    }

    logger.info(
        "SUCCESSFUL LOGIN | user_id=%s | email=%s",
        user_id,
        email
    )

    return json_success(
        response_data,
        200
    )

@app.route("/api/auth/me", methods=["GET"])
@require_authentication
def current_user():
    user = g.user
    user_id = user.get("id")

    profile, profile_error = get_profile(
        user_id
    )

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

@app.route("/api/auth/logout", methods=["POST"])
@require_authentication
def logout():
    success, error = supabase_logout(
        g.access_token
    )

    if not success:
        logger.error(
            "LOGOUT FAILED | user_id=%s | error=%s",
            g.user.get("id"),
            error
        )

        return json_error(
            "Logout failed.",
            500
        )

    logger.info(
        "LOGOUT SUCCESSFUL | user_id=%s",
        g.user.get("id")
    )

    return json_success({
        "message": "Logged out successfully."
    })

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

    url = f"{SUPABASE_AUTH_URL}/recover"

    payload = {
        "email": email
    }

    if FRONTEND_URL:
        payload["redirect_to"] = FRONTEND_URL

    try:
        response = http.post(
            url,
            headers=supabase_auth_headers(),
            json=payload,
            timeout=20
        )
    except requests.RequestException as exc:
        logger.error(
            "PASSWORD RECOVERY CONNECTION ERROR | error=%s",
            exc
        )

        return json_error(
            "Unable to process password recovery.",
            500
        )

    if response.status_code not in (200, 201, 204):
        logger.warning(
            "PASSWORD RECOVERY REQUEST FAILED | status=%s | error=%s",
            response.status_code,
            extract_supabase_error(response)
        )

    return json_success({
        "message": (
            "If an account exists for this email, "
            "a password reset email will be sent."
        )
    })

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
            timeout=20
        )
    except requests.RequestException as exc:
        logger.error(
            "TOKEN REFRESH CONNECTION ERROR | error=%s",
            exc
        )

        return json_error(
            "Unable to refresh authentication session.",
            500
        )

    if response.status_code != 200:
        error = extract_supabase_error(response)

        logger.warning(
            "TOKEN REFRESH FAILED | status=%s | error=%s",
            response.status_code,
            error
        )

        return json_error(
            error,
            401
        )

    try:
        data = response.json()
    except Exception:
        return json_error(
            "Invalid response from authentication service.",
            500
        )

    session = extract_session(data)

    if not session:
        return json_error(
            "Authentication service returned no refreshed session.",
            500
        )

    return json_success({
        "message": "Session refreshed successfully.",
        "session": session
    })

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
        "UNHANDLED SERVER ERROR | error=%s",
        error
    )

    return json_error(
        "Internal server error.",
        500
    )

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
