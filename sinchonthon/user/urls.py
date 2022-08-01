from django.urls import path
from . import views

urlpatterns = [
    #path('kakaologin', views.index, name='kakaologin'),
    path('kakaoLoginLogic', views.kakaoLoginLogic, name='kakaologic'),
    path('kakaoLoginLogicRedirect/', views.kakaoLoginLogicRedirect, name='kakaoredirect'),
    path('kakaoLogout/',views.kakaoLogout, name='kakaologout'),
    path('kakaologinredirect', views.index, name='kakaredirecting'),
    path('myInformation',views.myInformation,name='myInformation'),
]