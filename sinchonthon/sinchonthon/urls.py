"""sinchonthon URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.0/topics/http/urls/
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
# from django.urls.conf import include
from django.contrib import admin
from django.urls import path, include
from sinchonsite.views import main
import user.views
from rest_framework_jwt.views import obtain_jwt_token, verify_jwt_token, refresh_jwt_token


urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/token/', obtain_jwt_token),
    path('api/token/verify/', verify_jwt_token),
    path('api/token/refresh/', refresh_jwt_token),
    path('', include('user.urls') ),
    path('', main, name='main'),

    
    # social login
    #path('accounts/login', user.views.login_view, name='login'),
    #path('accounts/logout', user.views.logout_view, name='logout'),
    #path('accounts/signup', user.views.signup_view, name='signup'),
    # path('user/', include('user.urls')),
    #path('accounts/', include('allauth.urls')),
]
