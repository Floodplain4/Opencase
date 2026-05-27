import os
from pathlib import Path
from tempfile import NamedTemporaryFile
from urllib.parse import urlencode

from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.middleware.sessions import SessionMiddleware

from . import database as db
from .security import constant_time_equals, create_csrf_token, create_session_token, is_default_secret, read_session_token, secure_cookies_enabled, verify_password

app = FastAPI(title="Lenovo Case Tracker Web")
app.add_middleware(SessionMiddleware, secret_key=os.environ.get("LCT_SECRET_KEY", "dev-only-change-this-secret"))
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent / "templates"))

if secure_cookies_enabled():
    app.add_middleware(HTTPSRedirectMiddleware)

oauth = OAuth()
if os.environ.get("GOOGLE_CLIENT_ID") and os.environ.get("GOOGLE_CLIENT_SECRET"):
    oauth.register(
        name="google",
        client_id=os.environ["GOOGLE_CLIENT_ID"],
        client_secret=os.environ["GOOGLE_CLIENT_SECRET"],
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )

STATUS_COLORS = {"Total":"total","Ordered":"ordered","Pending":"pending","Replaced":"replaced","Returned":"returned","Complete":"complete","Follow-ups":"followup","Repeat Serials":"repeat","Open":"pending","Complete %":"complete","Top Part":"total"}


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    if secure_cookies_enabled():
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


def set_session_cookie(response: RedirectResponse, user_id: int) -> None:
    response.set_cookie("lct_session", create_session_token(user_id), httponly=True, samesite="lax", secure=secure_cookies_enabled(), max_age=60 * 60 * 8)


def set_csrf_cookie(response: Response, token: str) -> None:
    response.set_cookie("csrf_token", token, httponly=True, samesite="lax", secure=secure_cookies_enabled(), max_age=60 * 60 * 8)


def require_csrf(request: Request, csrf_token: str) -> None:
    if not constant_time_equals(request.cookies.get("csrf_token"), csrf_token):
        raise HTTPException(status_code=403, detail="Invalid CSRF token.")


def selected_parts_from_form(parts: list[str] | None) -> list[str]:
    return parts or []


def cases_url(search: str = "", status: str = "All", part: str = "All", hide_complete: bool = True, followups_only: bool = False) -> str:
    params = {"search": search, "status": status, "part": part, "hide_complete": str(hide_complete).lower(), "followups_only": str(followups_only).lower()}
    return "/cases?" + urlencode(params)


def current_user(request: Request) -> dict:
    user_id = read_session_token(request.cookies.get("lct_session"))
    user = db.get_user_by_id(user_id) if user_id else None
    if not user:
        raise HTTPException(status_code=307, headers={"Location": "/login"})
    return user


def current_user_optional(request: Request) -> dict | None:
    user_id = read_session_token(request.cookies.get("lct_session"))
    return db.get_user_by_id(user_id) if user_id else None


def csrf_context(request: Request) -> dict:
    token = request.cookies.get("csrf_token") or create_csrf_token()
    return {"csrf_token": token}


def template(request: Request, name: str, context: dict, set_cookie: bool = True):
    ctx = csrf_context(request)
    ctx.update(context)
    response = templates.TemplateResponse(request, name, ctx)
    if set_cookie:
        set_csrf_cookie(response, ctx["csrf_token"])
    return response


def admin_required(user: dict) -> None:
    if user["role"] != "admin":
        raise HTTPException(status_code=403)


@app.on_event("startup")
def startup() -> None:
    db.initialize_database()


@app.get("/login")
def login_page(request: Request):
    if current_user_optional(request):
        return RedirectResponse("/", status_code=303)
    return template(request, "login.html", {"user": None, "error": "", "google_enabled": hasattr(oauth, "google"), "local_auth_enabled": os.environ.get("LOCAL_AUTH_ENABLED", "false").strip().lower() == "true"})


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...), csrf_token: str = Form(...)):
    require_csrf(request, csrf_token)
    if os.environ.get("LOCAL_AUTH_ENABLED", "false").strip().lower() != "true":
        return template(request, "login.html", {"user": None, "error": "Local login is disabled. Use Google login.", "google_enabled": hasattr(oauth, "google"), "local_auth_enabled": False})
    user = db.get_user_by_username(username)
    if not user or not verify_password(password, user["password_hash"]):
        return template(request, "login.html", {"user": None, "error": "Invalid username or password.", "google_enabled": hasattr(oauth, "google"), "local_auth_enabled": os.environ.get("LOCAL_AUTH_ENABLED", "false").strip().lower() == "true"})
    redirect = RedirectResponse("/", status_code=303)
    set_session_cookie(redirect, user["id"])
    return redirect


@app.get("/auth/google/login")
async def google_login(request: Request):
    if not hasattr(oauth, "google"):
        raise HTTPException(status_code=503, detail="Google OAuth is not configured.")
    redirect_uri = os.environ.get("GOOGLE_REDIRECT_URI", "http://127.0.0.1:8000/auth/google/callback")
    return await oauth.google.authorize_redirect(request, redirect_uri)


@app.get("/auth/google/callback")
async def google_callback(request: Request):
    if not hasattr(oauth, "google"):
        raise HTTPException(status_code=503, detail="Google OAuth is not configured.")
    try:
        token = await oauth.google.authorize_access_token(request)
        userinfo = token.get("userinfo")
    except OAuthError:
        raise HTTPException(status_code=400, detail="Google login failed.")
    email = userinfo.get("email")
    display_name = userinfo.get("name") or email
    allowed_domain = os.environ.get("ALLOWED_EMAIL_DOMAIN", "").strip().lower()
    if allowed_domain and not email.lower().endswith("@" + allowed_domain):
        raise HTTPException(status_code=403, detail="Email domain is not allowed.")
    user = db.create_or_get_oauth_user(email, display_name)
    if not user:
        raise HTTPException(status_code=403, detail="This Google account is not allowed. Ask an admin to add your email first.")
    redirect = RedirectResponse("/", status_code=303)
    set_session_cookie(redirect, user["id"])
    return redirect


@app.post("/logout")
def logout(request: Request, csrf_token: str = Form(...)):
    require_csrf(request, csrf_token)
    redirect = RedirectResponse("/login", status_code=303)
    redirect.delete_cookie("lct_session")
    return redirect


@app.get("/")
def dashboard(request: Request, user: dict = Depends(current_user)):
    return template(request, "dashboard.html", {"user": user, "warning_default_secret": is_default_secret(), "counts": db.dashboard_counts(), "repeats": db.repeat_serial_groups(), "oldest_open": db.oldest_open_cases(limit=25), "status_colors": STATUS_COLORS})


@app.get("/cases")
def cases(request: Request, search: str = "", status: str = "All", part: str = "All", hide_complete: bool = True, followups_only: bool = False, user: dict = Depends(current_user)):
    rows = db.list_cases(search=search, status=status, part=part, hide_complete=hide_complete, followups_only=followups_only)
    analytics_cases = db.list_cases(hide_complete=hide_complete, followups_only=followups_only)
    return template(request, "cases.html", {"user": user, "cases": rows, "analytics": db.analytics(analytics_cases), "status_colors": STATUS_COLORS, "search": search, "status": status, "part": part, "hide_complete": hide_complete, "followups_only": followups_only, "statuses": ["All"] + db.STATUS_OPTIONS, "parts": ["All"] + db.PART_OPTIONS + ["Other"], "repeat_serials": set(db.repeat_serial_groups().keys())})


@app.get("/cases/new")
def new_case(request: Request, user: dict = Depends(current_user)):
    return template(request, "case_form.html", {"user": user, "mode": "new", "case": None, "statuses": db.STATUS_OPTIONS, "parts": db.PART_OPTIONS, "selected_parts": [], "other": "", "user_notes": "", "errors": []})


@app.post("/cases/new")
def create_case(request: Request, work_order: str = Form(...), serial_number: str = Form(...), status: str = Form(...), parts: list[str] | None = Form(None), other: str = Form(""), notes: str = Form(""), csrf_token: str = Form(...), user: dict = Depends(current_user)):
    require_csrf(request, csrf_token)
    selected_parts = selected_parts_from_form(parts)
    errors = db.validate_case_fields(work_order, serial_number, status)
    if errors:
        return template(request, "case_form.html", {"user": user, "mode": "new", "case": {"work_order": work_order, "serial_number": serial_number, "status": status}, "statuses": db.STATUS_OPTIONS, "parts": db.PART_OPTIONS, "selected_parts": selected_parts, "other": other, "user_notes": notes, "errors": errors})
    db.create_case(work_order, serial_number, status, selected_parts, other, notes, changed_by=user["display_name"])
    return RedirectResponse(cases_url(), status_code=303)


@app.get("/cases/{case_id}/edit")
def edit_case(request: Request, case_id: int, user: dict = Depends(current_user)):
    case = db.get_case(case_id)
    if not case:
        return RedirectResponse(cases_url(), status_code=303)
    selected_parts, other, user_notes = db.parse_notes_field(case["notes"])
    return template(request, "case_form.html", {"user": user, "mode": "edit", "case": case, "history": db.get_status_history(case_id), "statuses": db.STATUS_OPTIONS, "parts": db.PART_OPTIONS, "selected_parts": selected_parts, "other": other, "user_notes": user_notes, "errors": []})


@app.post("/cases/{case_id}/edit")
def update_case(request: Request, case_id: int, work_order: str = Form(...), serial_number: str = Form(...), status: str = Form(...), parts: list[str] | None = Form(None), other: str = Form(""), notes: str = Form(""), csrf_token: str = Form(...), user: dict = Depends(current_user)):
    require_csrf(request, csrf_token)
    selected_parts = selected_parts_from_form(parts)
    errors = db.validate_case_fields(work_order, serial_number, status)
    if errors:
        case = db.get_case(case_id) or {"id": case_id}
        case.update({"work_order": work_order, "serial_number": serial_number, "status": status})
        return template(request, "case_form.html", {"user": user, "mode": "edit", "case": case, "statuses": db.STATUS_OPTIONS, "parts": db.PART_OPTIONS, "selected_parts": selected_parts, "other": other, "user_notes": notes, "errors": errors})
    db.update_case(case_id, work_order, serial_number, status, selected_parts, other, notes, changed_by=user["display_name"])
    return RedirectResponse(cases_url(), status_code=303)


@app.post("/cases/{case_id}/delete")
def delete_case(request: Request, case_id: int, csrf_token: str = Form(...), user: dict = Depends(current_user)):
    require_csrf(request, csrf_token)
    db.delete_case(case_id)
    return RedirectResponse(cases_url(), status_code=303)


@app.post("/cases/{case_id}/status")
def update_status(request: Request, case_id: int, status: str = Form(...), csrf_token: str = Form(...), user: dict = Depends(current_user)):
    require_csrf(request, csrf_token)
    if status in db.STATUS_OPTIONS:
        db.update_status(case_id, status, changed_by=user["display_name"])
    return RedirectResponse(cases_url(), status_code=303)


@app.post("/cases/{case_id}/followup")
def toggle_followup(request: Request, case_id: int, followup: str = Form("false"), csrf_token: str = Form(...), user: dict = Depends(current_user)):
    require_csrf(request, csrf_token)
    db.set_followup(case_id, followup == "true")
    return RedirectResponse(cases_url(), status_code=303)


@app.get("/repeats")
def repeats(request: Request, user: dict = Depends(current_user)):
    rows = [{"serial": s, "count": len(r), "work_orders": ", ".join(x["work_order"] for x in r), "statuses": ", ".join(x["status"] for x in r), "latest_timestamp": r[0]["timestamp"] if r else ""} for s, r in db.repeat_serial_groups().items()]
    return template(request, "repeats.html", {"user": user, "repeat_rows": rows})


@app.get("/analytics")
def analytics_page(request: Request, user: dict = Depends(current_user)):
    return template(request, "analytics.html", {"user": user, "analytics": db.analytics(), "counts": db.dashboard_counts(), "parts": db.part_breakdown(), "aging": db.aging_buckets(), "status_colors": STATUS_COLORS})


@app.get("/account")
def account_page(request: Request, user: dict = Depends(current_user)):
    return template(request, "account.html", {"user": user, "error": "", "message": ""})


@app.post("/account/password")
def account_password(request: Request, current_password: str = Form(...), new_password: str = Form(...), csrf_token: str = Form(...), user: dict = Depends(current_user)):
    require_csrf(request, csrf_token)
    db_user = db.get_user_by_username(user["username"])
    if not db_user or not verify_password(current_password, db_user["password_hash"]):
        return template(request, "account.html", {"user": user, "error": "Current password was incorrect.", "message": ""})
    if len(new_password) < 10:
        return template(request, "account.html", {"user": user, "error": "New password must be at least 10 characters.", "message": ""})
    db.change_user_password(user["id"], new_password)
    return template(request, "account.html", {"user": user, "error": "", "message": "Password changed."})


@app.get("/users")
def users_page(request: Request, user: dict = Depends(current_user)):
    admin_required(user)
    return template(request, "users.html", {"user": user, "users": db.list_users(), "error": ""})


@app.post("/users")
def create_user(request: Request, username: str = Form(...), display_name: str = Form(...), password: str = Form(...), role: str = Form("tech"), email: str = Form(""), csrf_token: str = Form(...), user: dict = Depends(current_user)):
    require_csrf(request, csrf_token)
    admin_required(user)
    try:
        db.create_user(username, display_name, password, role, email)
        return RedirectResponse("/users", status_code=303)
    except Exception as e:
        return template(request, "users.html", {"user": user, "users": db.list_users(), "error": f"Could not create user: {e}"})


@app.post("/users/{user_id}/update")
def update_user(request: Request, user_id: int, display_name: str = Form(...), role: str = Form("tech"), is_active: str = Form("false"), csrf_token: str = Form(...), user: dict = Depends(current_user)):
    require_csrf(request, csrf_token)
    admin_required(user)
    if user_id == user["id"] and role != "admin":
        raise HTTPException(status_code=400, detail="You cannot remove your own admin role.")
    db.update_user(user_id, display_name, role, is_active == "true")
    return RedirectResponse("/users", status_code=303)


@app.post("/users/{user_id}/reset-password")
def reset_password(request: Request, user_id: int, new_password: str = Form(...), csrf_token: str = Form(...), user: dict = Depends(current_user)):
    require_csrf(request, csrf_token)
    admin_required(user)
    if len(new_password) < 10:
        return template(request, "users.html", {"user": user, "users": db.list_users(), "error": "Password must be at least 10 characters."})
    db.reset_user_password(user_id, new_password)
    return RedirectResponse("/users", status_code=303)


@app.post("/users/{user_id}/delete")
def delete_user(request: Request, user_id: int, csrf_token: str = Form(...), user: dict = Depends(current_user)):
    require_csrf(request, csrf_token)
    admin_required(user)
    if user_id == user["id"]:
        raise HTTPException(status_code=400, detail="You cannot delete your own account.")
    db.delete_user(user_id)
    return RedirectResponse("/users", status_code=303)


@app.get("/backups")
def backups_page(request: Request, user: dict = Depends(current_user)):
    admin_required(user)
    return template(request, "backups.html", {"user": user, "backups": db.list_backups(), "message": ""})


@app.post("/backups/create")
def create_backup(request: Request, csrf_token: str = Form(...), user: dict = Depends(current_user)):
    require_csrf(request, csrf_token)
    admin_required(user)
    db.create_backup()
    return RedirectResponse("/backups", status_code=303)


@app.get("/backups/download/{filename}")
def download_backup(filename: str, user: dict = Depends(current_user)):
    admin_required(user)
    path = db.backup_path(filename)
    if not path:
        raise HTTPException(status_code=404)
    return FileResponse(path, media_type="application/octet-stream", filename=path.name)


@app.get("/export")
def export_csv(user: dict = Depends(current_user)):
    export_path = db.project_root() / "lenovo_cases_export.csv"
    db.export_csv_file(export_path)
    return FileResponse(export_path, media_type="text/csv", filename="lenovo_cases_export.csv")


@app.get("/import")
def import_page(request: Request, user: dict = Depends(current_user)):
    return template(request, "import.html", {"user": user, "message": ""})


@app.post("/import")
async def import_csv(request: Request, file: UploadFile = File(...), csrf_token: str = Form(...), user: dict = Depends(current_user)):
    require_csrf(request, csrf_token)
    suffix = Path(file.filename or "upload.csv").suffix or ".csv"
    with NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(await file.read())
        tmp_path = Path(tmp.name)
    try:
        imported, skipped = db.import_csv_file(tmp_path)
        message = f"Imported {imported} entries. Skipped {skipped} blank/unusable rows."
    finally:
        tmp_path.unlink(missing_ok=True)
    return template(request, "import.html", {"user": user, "message": message})
