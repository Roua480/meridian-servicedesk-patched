from django.urls import path
from helpdesk.views import token_auth

urlpatterns = [
    path("api/whoami/", token_auth.whoami),
    path("auth/forgot/", token_auth.forgot_password),
    path("auth/reset/", token_auth.reset_password),
]
