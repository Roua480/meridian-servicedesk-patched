import secrets

SECRET_KEY = secrets.token_urlsafe(48)
MERIDIAN_TOKEN_KEY = secrets.token_urlsafe(48)
INSTALLED_APPS = [
    "django.contrib.auth", "django.contrib.contenttypes", "django.contrib.sites",
    "helpdesk",
]
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
DEFAULT_AUTO_FIELD = "django.db.models.AutoField"
ROOT_URLCONF = "tests.auth_urls"
EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
DEFAULT_FROM_EMAIL = "support@example.test"
USE_TZ = True
SITE_ID = 1
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
]
HELPDESK_TEAMS_MODE_ENABLED = False
