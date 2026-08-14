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
FRONTEND_URL = os.getenv(
    "FRONTEND_URL",
    "https://abn-kappa.vercel.app"
).rstrip("/")

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
            "Missing required environment variables: " + ", ".join(missing)
        )

validate_environment()

SUPABASE_URL = SUPABASE_URL.rstrip("/")
SUPABASE_AUTH_URL = f"{SUPABASE_URL}/auth/v1"
SUPABASE_REST_URL = f"{SUPABASE_URL}/rest/v1"

CORS(
    app,
    resources={
        r"/api/*": {
            "origins": [
                FRONTEND_URL,
                "https://abn-kappa.vercel.app"
            ]
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
        data = request.get_json(silent=True)

        return data if isinstance(data, dict) else None

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
    if not email or len(email) > MAX_EMAIL_LENGTH:
        return False

    return re.match(
        r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
        email
    ) is not None

def validate_password(password):
    return (
        isinstance(password, str)
        and len(password) >= MIN_PASSWORD_LENGTH
    )

def validate_username(username):
    if not username:
        return False

    if len(username) < 3 or len(username) > MAX_USERNAME_LENGTH:
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
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"

    return headers

def supabase_database_headers(
    use_service_role=True,
    access_token=None
):
    key = (
        SUPABASE_SERVICE_ROLE_KEY
        if use_service_role
        else SUPABASE_ANON_KEY
    )

    headers = {
        "apikey": key,
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Prefer": "return=representation"
    }

    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"

    return headers

def extract_supabase_error(response):
    try:
        data = response.json()

    except Exception:
        text = response.text.strip()

        return (
            text[:500]
            if text
            else "Supabase request failed."
        )

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

    return "Supabase request failed."

def build_session(data):
    if not isinstance(data, dict):
        return None

    access_token = data.get("access_token")
    refresh_token = data.get("refresh_token")

    if not access_token:
        return None

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": data.get("expires_in"),
        "expires_at": data.get("expires_at"),
        "token_type": data.get(
            "token_type",
            "bearer"
        )
    }

def supabase_signup(
    email,
    password,
    user_metadata
):
    url = f"{SUPABASE_AUTH_URL}/signup"

    payload = {
        "email": email,
        "password": password,
        "data": user_metadata
    }

    if FRONTEND_URL and FRONTEND_URL != "*":
        payload["redirect_to"] = FRONTEND_URL

    logger.info(
        "SUPABASE SIGNUP REQUEST | email=%s",
        email
    )

    try:
        response = http.post(
            url,
            headers=supabase_auth_headers(),
            json=payload,
            timeout=20
        )

    except requests.RequestException as exc:
        logger.error(
            "SUPABASE SIGNUP CONNECTION ERROR | email=%s | error=%s",
            email,
            exc
        )

        return None, "Unable to connect to authentication service."

    try:
        response_data = response.json()

    except Exception:
        response_data = {}

    logger.info(
        "SUPABASE SIGNUP RESPONSE | email=%s | status=%s",
        email,
        response.status_code
    )

    if response.status_code not in (200, 201):
        error = extract_supabase_error(response)

        logger.warning(
            "SUPABASE SIGNUP REJECTED | email=%s | status=%s | error=%s",
            email,
            response.status_code,
            error
        )

        return None, error

    return response_data, None

def supabase_login(
    email,
    password
):
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
            "SUPABASE LOGIN CONNECTION ERROR | email=%s | error=%s",
            email,
            exc
        )

        return None, "Unable to connect to authentication service."

    try:
        data = response.json()

    except Exception:
        data = {}

    if response.status_code != 200:
        error = extract_supabase_error(response)

        logger.warning(
            "SUPABASE LOGIN FAILED | email=%s | status=%s | error=%s",
            email,
            response.status_code,
            error
        )

        return None, error

    user = data.get("user")
    session = build_session(data)

    logger.info(
        "SUPABASE LOGIN SUCCESS | email=%s | user_id=%s | session=%s",
        email,
        user.get("id") if isinstance(user, dict) else None,
        bool(session)
    )

    return {
        "user": user,
        "session": session,
        "raw": data
    }, None

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
        return None, extract_supabase_error(response)

    try:
        return response.json(), None

    except Exception:
        return None, "Invalid authentication response."

def supabase_update_password(
    access_token,
    password
):
    url = f"{SUPABASE_AUTH_URL}/user"

    payload = {
        "password": password
    }

    try:
        response = http.put(
            url,
            headers=supabase_auth_headers(
                access_token=access_token
            ),
            json=payload,
            timeout=20
        )

    except requests.RequestException as exc:
        logger.error(
            "SUPABASE PASSWORD UPDATE CONNECTION ERROR | error=%s",
            exc
        )

        return None, "Unable to connect to authentication service."

    if response.status_code not in (200, 201):
        error = extract_supabase_error(response)

        logger.warning(
            "SUPABASE PASSWORD UPDATE FAILED | status=%s | error=%s",
            response.status_code,
            error
        )

        return None, error

    try:
        data = response.json()

    except Exception:
        data = {}

    return data, None

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
        return False, extract_supabase_error(response)

    return True, None

def create_profile(
    user_id,
    email,
    full_name,
    username
):
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

        if isinstance(data, list) and data:
            return data[0], None

        if isinstance(data, dict):
            return data, None

        return None, "Invalid database response."

    except Exception:
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
            headers=supabase_database_headers(
                use_service_role=True
            ),
            timeout=20
        )

    except requests.RequestException as exc:
        logger.error(
            "PROFILE LOOKUP ERROR | user_id=%s | error=%s",
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

        if not isinstance(data, list) or not data:
            return None, None

        return data[0], None

    except Exception:
        return None, "Invalid database response."

def check_username_exists(username):
    url = f"{SUPABASE_REST_URL}/profiles"

    params = {
        "username": f"eq.{username}",
        "select": "id",
        "limit": "1"
    }

    try:
        response = http.get(
            url,
            params=params,
            headers=supabase_database_headers(
                use_service_role=True
            ),
            timeout=20
        )

    except requests.RequestException as exc:
        logger.error(
            "USERNAME LOOKUP ERROR | username=%s | error=%s",
            username,
            exc
        )

        return None, "Unable to check username."

    if response.status_code != 200:
        error = extract_supabase_error(response)

        logger.error(
            "USERNAME LOOKUP FAILED | username=%s | error=%s",
            username,
            error
        )

        return None, error

    try:
        data = response.json()

        return bool(
            isinstance(data, list) and data
        ), None

    except Exception:
        return None, "Invalid database response."

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

    password = data.get(
        "password",
        ""
    )

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
            "Username must be 3-50 characters and contain only letters, numbers, underscores or periods.",
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
        email=email,
        password=password,
        user_metadata=user_metadata
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

        if "rate limit" in lower_error:
            return json_error(
                "Too many signup emails have been requested recently. Please wait a while before trying again.",
                429
            )

        logger.error(
            "SIGNUP FAILED | email=%s | error=%s",
            email,
            auth_error
        )

        return json_error(
            auth_error,
            400
        )

    if not auth_data:
        logger.error(
            "SIGNUP FAILED | Supabase returned no response data | email=%s",
            email
        )

        return json_error(
            "Account creation could not be completed.",
            500
        )

    user = auth_data.get("user")
    session = build_session(auth_data)

    if not session:
        if user and user.get("id"):
            user_id = user.get("id")

            profile, profile_error = create_profile(
                user_id=user_id,
                email=email,
                full_name=full_name,
                username=username
            )

            if profile_error:
                logger.warning(
                    "PROFILE DEFERRED | user_id=%s | error=%s",
                    user_id,
                    profile_error
                )

        logger.info(
            "SIGNUP SUCCESS - EMAIL VERIFICATION REQUIRED | email=%s",
            email
        )

        return json_success({
            "verification_required": True,
            "message": "Account created successfully. Please check your email for the authentication link to verify your account. After verification, return here and sign in.",
            "user": None,
            "session": None
        }, 201)

    if not user or not user.get("id"):
        logger.error(
            "SIGNUP FAILED | Supabase returned authentication tokens without a user | email=%s",
            email
        )

        return json_error(
            "Account creation returned an invalid authentication response.",
            500
        )

    user_id = user.get("id")

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

        return json_error(
            "Account was created, but your profile could not be saved.",
            500
        )

    logger.info(
        "SIGNUP SUCCESS | user_id=%s | email=%s | session=True",
        user_id,
        email
    )

    return json_success({
        "message": "Account created and authenticated successfully.",
        "verification_required": False,
        "user": {
            "id": user_id,
            "email": user.get("email") or email,
            "full_name": full_name,
            "username": username
        },
        "session": session
    }, 201)

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

    password = data.get(
        "password",
        ""
    )

    if not validate_email(email):
        return json_error(
            "Please provide a valid email address.",
            400
        )

    if not isinstance(password, str) or not password:
        return json_error(
            "Password is required.",
            400
        )

    auth_data, auth_error = supabase_login(
        email,
        password
    )

    if auth_error:
        lower_error = auth_error.lower()

        if (
            "email not confirmed" in lower_error
            or "email_not_confirmed" in lower_error
            or "confirm your email" in lower_error
            or "email confirmation" in lower_error
        ):
            return json_error(
                "Please check your email and click the authentication link to verify your account before signing in.",
                403,
                verification_required=True
            )

        logger.warning(
            "LOGIN REJECTED | email=%s | error=%s",
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
    session = auth_data.get("session")

    if not user:
        return json_error(
            "Authentication succeeded but no user was returned.",
            500
        )

    if not session:
        logger.warning(
            "LOGIN REQUIRES EMAIL VERIFICATION | email=%s | user_id=%s",
            email,
            user.get("id")
        )

        return json_error(
            "Please check your email and click the authentication link to verify your account before signing in.",
            403,
            verification_required=True
        )

    user_id = user.get("id")

    if not user_id:
        return json_error(
            "Authentication succeeded but no user ID was returned.",
            500
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
            "Unable to retrieve user profile.",
            500
        )

    metadata = user.get(
        "user_metadata",
        {}
    )

    if not profile:
        metadata_full_name = clean_string(
            metadata.get("full_name"),
            MAX_NAME_LENGTH
        )

        metadata_username = normalize_username(
            clean_string(
                metadata.get("username"),
                MAX_USERNAME_LENGTH
            )
        )

        if (
            metadata_full_name
            and validate_username(metadata_username)
        ):
            profile, create_error = create_profile(
                user_id=user_id,
                email=user.get("email") or email,
                full_name=metadata_full_name,
                username=metadata_username
            )

            if create_error:
                logger.warning(
                    "PROFILE AUTO-CREATION FAILED | user_id=%s | error=%s",
                    user_id,
                    create_error
                )

        if not profile:
            profile = {
                "id": user_id,
                "email": user.get("email") or email,
                "full_name": metadata_full_name or "",
                "username": metadata_username or ""
            }

            logger.warning(
                "LOGIN SUCCESS WITHOUT PROFILE ROW | user_id=%s | email=%s",
                user_id,
                email
            )

    response_data = {
        "message": "Login successful.",
        "verification_required": False,
        "user": {
            "id": user_id,
            "email": user.get("email") or email,
            "full_name": profile.get("full_name", ""),
            "username": profile.get("username", "")
        },
        "session": {
            "access_token": session.get("access_token"),
            "refresh_token": session.get("refresh_token"),
            "expires_in": session.get("expires_in"),
            "expires_at": session.get("expires_at"),
            "token_type": session.get(
                "token_type",
                "bearer"
            )
        }
    }

    logger.info(
        "SUCCESSFUL LOGIN | user_id=%s | email=%s | session=True",
        user_id,
        email
    )

    return json_success(
        response_data,
        200
    )

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

    if FRONTEND_URL and FRONTEND_URL != "*":
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
        error = extract_supabase_error(response)

        logger.warning(
            "PASSWORD RECOVERY REQUEST FAILED | status=%s | error=%s",
            response.status_code,
            error
        )

        if response.status_code == 429:
            return json_error(
                "Too many password reset requests. Please wait before requesting another email.",
                429
            )

        return json_error(
            "Unable to process password recovery.",
            502
        )

    logger.info(
        "PASSWORD RECOVERY REQUEST ACCEPTED | email=%s",
        email
    )

    return json_success({
        "message": "If an account exists for this email, a password reset email will be sent."
    })

@app.route("/api/auth/reset-password", methods=["POST"])
def reset_password():
    data = get_json_body()

    if not data:
        return json_error(
            "Request body must be valid JSON.",
            400
        )

    password = data.get(
        "password",
        ""
    )

    if not validate_password(password):
        return json_error(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters.",
            400
        )

    authorization = request.headers.get(
        "Authorization",
        ""
    )

    if not authorization:
        return json_error(
            "Password reset authentication token is required.",
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
            "Password reset authentication token is required.",
            401
        )

    user, user_error = supabase_get_user(
        access_token
    )

    if user_error or not user:
        logger.warning(
            "PASSWORD RESET REJECTED | invalid recovery token | error=%s",
            user_error
        )

        return json_error(
            "Your password reset link is invalid or has expired. Please request a new password reset email.",
            401
        )

    updated_user, update_error = supabase_update_password(
        access_token=access_token,
        password=password
    )

    if update_error:
        logger.error(
            "PASSWORD RESET FAILED | user_id=%s | error=%s",
            user.get("id"),
            update_error
        )

        lower_error = update_error.lower()

        if (
            "password" in lower_error
            and "weak" in lower_error
        ):
            return json_error(
                "The new password does not meet the password security requirements.",
                400
            )

        return json_error(
            update_error,
            400
        )

    logger.info(
        "PASSWORD RESET SUCCESS | user_id=%s",
        user.get("id")
    )

    return json_success({
        "message": "Your password has been updated successfully."
    })

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

    metadata = user.get(
        "user_metadata",
        {}
    )

    return json_success({
        "user": {
            "id": user.get("id"),
            "email": user.get("email"),
            "full_name": (
                profile.get("full_name")
                if profile
                else metadata.get("full_name", "")
            ),
            "username": (
                profile.get("username")
                if profile
                else metadata.get("username", "")
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
            "LOGOUT FAILED | error=%s",
            error
        )

        return json_error(
            "Logout failed.",
            500
        )

    return json_success({
        "message": "Logged out successfully."
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
            "TOKEN REFRESH FAILED | error=%s",
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

    session = build_session(data)

    if not session:
        return json_error(
            "Authentication service returned an invalid session.",
            401
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
