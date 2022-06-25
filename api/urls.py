from django.urls import path

from . import views
from api.controllers import userController

urlpatterns = [
    path("", views.test),
    path("auth/register", userController.register),
    path("auth/login", userController.login),
    path("auth/edit_profile", userController.edit_profile),
]
