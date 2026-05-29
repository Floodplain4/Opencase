import os
from collections import Counter
from pathlib import Path
from tempfile import NamedTemporaryFile
from urllib.parse import urlencode

from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.middleware.sessions import SessionMiddleware
from fastapi.staticfiles import StaticFiles

from . import database as db
from .security import constant_time_equals, create_csrf_token, create_session_token, is_default_secret, read_session_token, secure_cookies_enabled, verify_password

app = FastAPI(title="Lenovo Case Tracker Web")
app.mount("/static", StaticFiles(directory="app/static"), name="static")
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

DEMO_USERNAME = "demo"
DEMO_DISPLAY_NAME = "Demo User"
DEMO_EMAIL = "demo@lenovocasetracker.local"



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


def block_demo_user(user: dict) -> None:
    if user.get("username") == DEMO_USERNAME:
        raise HTTPException(status_code=403, detail="Demo user cannot make destructive changes.")



@app.on_event("startup")
def startup() -> None:
    db.initialize_database()


def demo_login_enabled() -> bool:
    return os.environ.get("DEMO_LOGIN_ENABLED", "true").strip().lower() == "true"


def ensure_demo_user() -> dict:
    existing = db.get_user_by_username(DEMO_USERNAME)
    if existing:
        return existing

    db.create_user(
        username=DEMO_USERNAME,
        display_name=DEMO_DISPLAY_NAME,
        password=os.urandom(24).hex(),
        role="tech",
        email=DEMO_EMAIL,
    )

    user = db.get_user_by_username(DEMO_USERNAME)
    if not user:
        raise HTTPException(status_code=500, detail="Demo user could not be created.")

    return user


@app.get("/login")
def login_page(request: Request):
    if current_user_optional(request):
        return RedirectResponse("/", status_code=303)
    return template(request, "login.html", {"user": None, "error": "", "google_enabled": hasattr(oauth, "google"), "local_auth_enabled": os.environ.get("LOCAL_AUTH_ENABLED", "false").strip().lower() == "true", "demo_enabled": demo_login_enabled()})


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...), csrf_token: str = Form(...)):
    require_csrf(request, csrf_token)
    if os.environ.get("LOCAL_AUTH_ENABLED", "false").strip().lower() != "true":
        return template(request, "login.html", {"user": None, "error": "Local login is disabled. Use Google login.", "google_enabled": hasattr(oauth, "google"), "local_auth_enabled": False, "demo_enabled": demo_login_enabled()})
    user = db.get_user_by_username(username)
    if not user or not verify_password(password, user["password_hash"]):
        return template(request, "login.html", {"user": None, "error": "Invalid username or password.", "google_enabled": hasattr(oauth, "google"), "local_auth_enabled": os.environ.get("LOCAL_AUTH_ENABLED", "false").strip().lower() == "true", "demo_enabled": demo_login_enabled()})
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


@app.get("/demo-login")
def demo_login():
    if not demo_login_enabled():
        raise HTTPException(status_code=404)

    user = ensure_demo_user()

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


def sorted_cases(rows: list[dict], sort: str = "work_order", direction: str = "asc") -> list[dict]:
    valid_sorts = {
        "work_order": "work_order",
        "serial_number": "serial_number",
        "status": "status",
        "parts": "parts",
        "notes": "user_notes",
        "timestamp": "timestamp",
        "followup": "followup",
    }

    sort_key = valid_sorts.get(sort, "work_order")
    reverse = direction == "desc"

    def normalize(value):
        if value is None:
            return ""
        if isinstance(value, bool):
            return int(value)
        return str(value).lower()

    return sorted(rows, key=lambda row: normalize(row.get(sort_key)), reverse=reverse)


def cases_redirect_url(
    sort: str = "work_order",
    direction: str = "asc",
    search: str = "",
    status: str = "All",
    part: str = "All",
    hide_complete: bool = True,
    followups_only: bool = False,
) -> str:
    return (
        f"/cases?"
        f"sort={sort}"
        f"&direction={direction}"
        f"&search={search}"
        f"&status={status}"
        f"&part={part}"
        f"&hide_complete={str(hide_complete).lower()}"
        f"&followups_only={str(followups_only).lower()}"
    )


@app.get("/cases")
def cases(
    request: Request,
    search: str = "",
    status: str = "All",
    part: str = "All",
    hide_complete: bool = True,
    followups_only: bool = False,
    sort: str = "work_order",
    direction: str = "asc",
    user: dict = Depends(current_user),
):
    rows = db.list_cases(
        search=search,
        status=status,
        part=part,
        hide_complete=hide_complete,
        followups_only=followups_only,
    )

    rows = sorted_cases(rows, sort=sort, direction=direction)

    analytics_cases = db.list_cases(
        hide_complete=hide_complete,
        followups_only=followups_only,
    )

    return template(
        request,
        "cases.html",
        {
            "user": user,
            "cases": rows,
            "analytics": db.analytics(analytics_cases),
            "status_colors": STATUS_COLORS,
            "search": search,
            "status": status,
            "part": part,
            "hide_complete": hide_complete,
            "followups_only": followups_only,
            "sort": sort,
            "direction": direction,
            "statuses": ["All"] + db.STATUS_OPTIONS,
            "parts": ["All"] + db.PART_OPTIONS + ["Other"],
            "repeat_serials": set(db.repeat_serial_groups().keys()),
        },
    )


@app.get("/cases/new")
def new_case(request: Request, user: dict = Depends(current_user)):
    return template(
        request,
        "case_form.html",
        {
            "user": user,
            "mode": "new",
            "case": None,
            "statuses": db.STATUS_OPTIONS,
            "parts": db.PART_OPTIONS,
            "selected_parts": [],
            "other": "",
            "user_notes": "",
            "errors": [],
        },
    )


@app.post("/cases/new")
def create_case(
    request: Request,
    work_order: str = Form(...),
    serial_number: str = Form(...),
    status: str = Form(...),
    parts: list[str] | None = Form(None),
    other: str = Form(""),
    notes: str = Form(""),
    csrf_token: str = Form(...),
    user: dict = Depends(current_user),
):
    require_csrf(request, csrf_token)

    selected_parts = selected_parts_from_form(parts)
    errors = db.validate_case_fields(work_order, serial_number, status)

    if errors:
        return template(
            request,
            "case_form.html",
            {
                "user": user,
                "mode": "new",
                "case": {
                    "work_order": work_order,
                    "serial_number": serial_number,
                    "status": status,
                },
                "statuses": db.STATUS_OPTIONS,
                "parts": db.PART_OPTIONS,
                "selected_parts": selected_parts,
                "other": other,
                "user_notes": notes,
                "errors": errors,
            },
        )

    db.create_case(
        work_order,
        serial_number,
        status,
        selected_parts,
        other,
        notes,
        changed_by=user["display_name"],
    )

    return RedirectResponse(
        cases_redirect_url(sort="work_order", direction="asc"),
        status_code=303,
    )


@app.get("/cases/{case_id}/edit")
def edit_case(request: Request, case_id: int, user: dict = Depends(current_user)):
    case = db.get_case(case_id)

    if not case:
        return RedirectResponse(
            cases_redirect_url(sort="work_order", direction="asc"),
            status_code=303,
        )

    selected_parts, other, user_notes = db.parse_notes_field(case["notes"])

    return template(
        request,
        "case_form.html",
        {
            "user": user,
            "mode": "edit",
            "case": case,
            "history": db.get_status_history(case_id),
            "statuses": db.STATUS_OPTIONS,
            "parts": db.PART_OPTIONS,
            "selected_parts": selected_parts,
            "other": other,
            "user_notes": user_notes,
            "errors": [],
        },
    )


@app.post("/cases/{case_id}/edit")
def update_case(
    request: Request,
    case_id: int,
    work_order: str = Form(...),
    serial_number: str = Form(...),
    status: str = Form(...),
    parts: list[str] | None = Form(None),
    other: str = Form(""),
    notes: str = Form(""),
    csrf_token: str = Form(...),
    user: dict = Depends(current_user),
):
    require_csrf(request, csrf_token)

    selected_parts = selected_parts_from_form(parts)
    errors = db.validate_case_fields(work_order, serial_number, status)

    if errors:
        case = db.get_case(case_id) or {"id": case_id}
        case.update(
            {
                "work_order": work_order,
                "serial_number": serial_number,
                "status": status,
            }
        )

        return template(
            request,
            "case_form.html",
            {
                "user": user,
                "mode": "edit",
                "case": case,
                "statuses": db.STATUS_OPTIONS,
                "parts": db.PART_OPTIONS,
                "selected_parts": selected_parts,
                "other": other,
                "user_notes": notes,
                "errors": errors,
            },
        )

    db.update_case(
        case_id,
        work_order,
        serial_number,
        status,
        selected_parts,
        other,
        notes,
        changed_by=user["display_name"],
    )

    return RedirectResponse(
        cases_redirect_url(sort="work_order", direction="asc"),
        status_code=303,
    )


@app.post("/cases/{case_id}/delete")
def delete_case(
    request: Request,
    case_id: int,
    csrf_token: str = Form(...),
    user: dict = Depends(current_user),
):
    require_csrf(request, csrf_token)
    block_demo_user(user)
    db.delete_case(case_id)

    return RedirectResponse(
        cases_redirect_url(sort="work_order", direction="asc"),
        status_code=303,
    )


@app.post("/cases/{case_id}/status")
def update_status(
    request: Request,
    case_id: int,
    status: str = Form(...),
    csrf_token: str = Form(...),
    user: dict = Depends(current_user),
):
    require_csrf(request, csrf_token)

    if status in db.STATUS_OPTIONS:
        db.update_status(case_id, status, changed_by=user["display_name"])

    return RedirectResponse(
        cases_redirect_url(sort="work_order", direction="asc"),
        status_code=303,
    )


@app.post("/cases/{case_id}/followup")
def toggle_followup(
    request: Request,
    case_id: int,
    followup: str = Form("false"),
    csrf_token: str = Form(...),
    user: dict = Depends(current_user),
):
    require_csrf(request, csrf_token)
    db.set_followup(case_id, followup == "true")

    return RedirectResponse(
        cases_redirect_url(sort="work_order", direction="asc"),
        status_code=303,
    )


@app.get("/repeats")
def repeats(request: Request, user: dict = Depends(current_user)):
    rows = []

    for serial, case_rows in db.repeat_serial_groups().items():
        part_counter = Counter()

        for case in case_rows:
            parts_text = case.get("parts") or "Unknown"
            parts = [part.strip() for part in parts_text.split(",") if part.strip()]

            if not parts:
                part_counter["Unknown"] += 1
            else:
                for part in parts:
                    part_counter[part] += 1

        parts_summary = " | ".join(
            f"{count} {part}{'' if count == 1 else 's'}"
            for part, count in part_counter.most_common()
        )

        rows.append(
            {
                "serial": serial,
                "count": len(case_rows),
                "work_orders": ", ".join(case["work_order"] for case in case_rows),
                "parts_summary": parts_summary or "None",
                "latest_timestamp": max((case["timestamp"] for case in case_rows), default=""),
            }
        )

    rows.sort(key=lambda row: row["count"], reverse=True)

    return template(request, "repeats.html", {"user": user, "repeat_rows": rows})



@app.get("/analytics")
def analytics_page(request: Request, user: dict = Depends(current_user)):
    return template(request, "analytics.html", {"user": user, "analytics": db.analytics(), "counts": db.dashboard_counts(), "parts": db.part_breakdown(), "aging": db.aging_buckets(), "status_colors": STATUS_COLORS})


@app.get("/users")
def users_page(request: Request, user: dict = Depends(current_user)):
    admin_required(user)
    return template(
        request,
        "users.html",
        {
            "user": user,
            "users": db.list_users(),
            "error": "",
        },
    )


@app.post("/users")
def create_user(
    request: Request,
    email: str = Form(...),
    display_name: str = Form(...),
    role: str = Form("tech"),
    csrf_token: str = Form(...),
    user: dict = Depends(current_user),
):
    require_csrf(request, csrf_token)
    admin_required(user)

    username = email.split("@")[0].strip().lower()

    try:
        db.create_user(
            username=username,
            display_name=display_name,
            password=os.urandom(24).hex(),
            role=role,
            email=email.strip().lower(),
        )
        return RedirectResponse("/users", status_code=303)
    except Exception as e:
        return template(
            request,
            "users.html",
            {
                "user": user,
                "users": db.list_users(),
                "error": f"Could not create user: {e}",
            },
        )


@app.post("/users/{user_id}/update")
def update_user(
    request: Request,
    user_id: int,
    display_name: str = Form(...),
    role: str = Form("tech"),
    is_active: str = Form("false"),
    csrf_token: str = Form(...),
    user: dict = Depends(current_user),
):
    require_csrf(request, csrf_token)
    admin_required(user)

    if user_id == user["id"] and role != "admin":
        raise HTTPException(
            status_code=400,
            detail="You cannot remove your own admin role.",
        )

    db.update_user(
        user_id=user_id,
        display_name=display_name,
        role=role,
        is_active=is_active == "true",
    )

    return RedirectResponse("/users", status_code=303)


@app.post("/users/{user_id}/delete")
def delete_user(
    request: Request,
    user_id: int,
    csrf_token: str = Form(...),
    user: dict = Depends(current_user),
):
    require_csrf(request, csrf_token)
    admin_required(user)

    if user_id == user["id"]:
        raise HTTPException(
            status_code=400,
            detail="You cannot delete your own account.",
        )

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
    block_demo_user(user)
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
