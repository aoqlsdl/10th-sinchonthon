from django.urls import path
from . import views

urlpatterns = [
    path('kakaologin', views.index, name='kakao'),
    path('kakaoLoginLogic', views.kakaoLoginLogic),
    path('kakaoLoginLogicRedirect/', views.kakaoLoginLogicRedirect),
    path('kakaoLogout/',views.kakaoLogout),
    path('kakaologinredirect', views.index, name='index'),
]