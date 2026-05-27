# Lenovo Case Tracker Web

Author/Publisher: Tyler Ledbetter

FastAPI web version of Lenovo Case Tracker with Google OAuth support and a public-GitHub-safe configuration model.

## Current security features

- Google OAuth / OpenID Connect login support
- No hardcoded production passwords
- First admin is created from environment variables
- Optional local login fallback, disabled by default
- Admin user management
- Create/manage/deactivate/delete users
- Admin password reset for local accounts
- User password change for local accounts
- Signed session cookies
- CSRF tokens for forms
- Security headers middleware
- Optional HTTPS redirect / secure cookies
- Database backup creation/download

## Local setup

```powershell
pip install -r requirements.txt
$Env:LCT_SECRET_KEY = "replace-with-long-random-secret"
$Env:LCT_ADMIN_EMAIL = "your-google-email@example.com"
$Env:LCT_ADMIN_DISPLAY_NAME = "Tyler Ledbetter"
uvicorn app.main:app --reload
```

Open:

```text
http://127.0.0.1:8000
```

## Google OAuth setup

Create an OAuth Web Application client in Google Cloud Console and set:

```powershell
$Env:GOOGLE_CLIENT_ID = "your-client-id"
$Env:GOOGLE_CLIENT_SECRET = "your-client-secret"
$Env:GOOGLE_REDIRECT_URI = "http://127.0.0.1:8000/auth/google/callback"
```

For production, the redirect URI should use your HTTPS app URL, for example:

```text
https://your-app-url/auth/google/callback
```

## Public GitHub safety

Do not commit:

- `.env`
- `lenovo_tracker.db`
- backups
- CSV exports
- real Lenovo serials/work orders
- internal screenshots
- OAuth client secrets

## Production warning

This is a stronger web-app baseline, but still review carefully before internet deployment. Use HTTPS, real environment secrets, backups, least-privilege Google OAuth settings, and preferably a managed database if this becomes more than a portfolio/demo app.
