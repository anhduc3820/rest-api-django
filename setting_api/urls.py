"""setting_api URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.0/topics/http/urls/
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
from django.urls import path
from apps.users import views as uv

version = "v1"

urlpatterns = [
    # User
    path(f"api/{version}/users/login/", uv.LoginUserAPI.as_view()),
    # path(f"api/{version}/users/logout/", uv.LogoutAPI.as_view()),
    path(f"api/{version}/create_user/", uv.CreateUser.as_view()),
    path(f"api/{version}/users/get_user/", uv.GetUserDetail.as_view()),

]
