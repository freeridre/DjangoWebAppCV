"""SenityProject URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.urls import path, include
from . import views


urlpatterns = [
    path("", views.login_user, name="login"),
    path("login/", views.login_user, name = "login"),
    path("register/", views.register_user, name="registration"),
    path("dashboard/", views.dashboard_user, name="dashboard"),
    path("logout/", views.logout_user, name="logout"),
    path("reset/", views.reset_password, name="resetPass"),
    path("activate/<uidb64>/<token>/", views.ActivateAccountView.as_view(), name="activate"),
    path("confirm_reset_password/<uidb64>/<token>/", views.ResetPasswordView.as_view(),
         name="confirm_reset_password"),
    path('resend_activation/<str:username>/', views.resend_activation_email, name='resend_activation_email'),
    path('google/api/passes/', views.google_wallet_callback, name='google_wallet_callback'),
]
