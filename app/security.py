import os
import secrets
from itsdangerous import BadSignature, URLSafeSerializer
from passlib.context import CryptContext

APP_SECRET_ENV = "LCT_SECRET_KEY"
DEFAULT_SECRET = "dev-only-change-this-secret"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_secret_key() -> str:
    return os.environ.get(APP_SECRET_ENV, DEFAULT_SECRET)


def is_default_secret() -> bool:
    return get_secret_key() == DEFAULT_SECRET


def secure_cookies_enabled() -> bool:
    return os.environ.get("LCT_SECURE_COOKIES", "false").strip().lower() == "true"


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def serializer() -> URLSafeSerializer:
    return URLSafeSerializer(get_secret_key(), salt="lct-session")


def create_session_token(user_id: int) -> str:
    nonce = secrets.token_hex(16)
    return serializer().dumps({"user_id": user_id, "nonce": nonce})


def read_session_token(token: str | None) -> int | None:
    if not token:
        return None
    try:
        data = serializer().loads(token)
        return int(data.get("user_id"))
    except (BadSignature, TypeError, ValueError):
        return None


def create_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def constant_time_equals(a: str | None, b: str | None) -> bool:
    if not a or not b:
        return False
    return secrets.compare_digest(a, b)
