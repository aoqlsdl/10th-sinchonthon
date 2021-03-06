from dataclasses import dataclass
from turtle import home
from django.shortcuts import redirect, render
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.contrib.auth import authenticate, login, logout
from django.http import HttpResponse, JsonResponse
from requests import RequestException
import json
from django.template import loader
import requests

# from sinchonthon.sinchonthon.settings import SOCIAL_OUTH_CONFIG
from .forms import RegisterForm

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny

def index(request):
    _context = {'check':False}
    if request.session.get('access_token'):
        _context['check'] = True
    return render(request, 'login.html', _context)

def kakaoLoginLogic(request):
    _restApiKey = '' # 입력필요
    _redirectUrl = 'http://127.0.0.1:8000/kakaoLoginLogicRedirect'
    _url = f'https://kauth.kakao.com/oauth/authorize?client_id={_restApiKey}&redirect_uri={_redirectUrl}&response_type=code'
    return redirect(_url)


def kakaoLoginLogicRedirect(request):
    _qs = request.GET['code']
    _restApiKey = '' # 입력필요
    _redirect_uri = 'http://127.0.0.1:8000/kakaoLoginLogicRedirect'
    _url = f'https://kauth.kakao.com/oauth/token?grant_type=authorization_code&client_id={_restApiKey}&redirect_uri={_redirect_uri}&code={_qs}'
    _res = requests.post(_url)
    _result = _res.json()
    request.session['access_token'] = _result['access_token']
    request.session.modified = True
    return render(request, 'loginSuccess.html')

def kakaoLogout(request):
    _token = request.session['access_token']
    _url = 'https://kapi.kakao.com/v1/user/logout'
    _header = {
      'Authorization': f'bearer {_token}'
    }
    # _url = 'https://kapi.kakao.com/v1/user/unlink'
    # _header = {
    #   'Authorization': f'bearer {_token}',
    # }
    _res = requests.post(_url, headers=_header)
    _result = _res.json()
    if _result.get('id'):
        del request.session['access_token']
        return render(request, 'loginoutSuccess.html')
    else:
        return render(request, 'logoutError.html')

# Create your views here.
def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(request=request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(request=request, username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('home')
        else:
            form = AuthenticationForm()
            return render(request, 'login.html', {'form':form})

def logout_view(request):
    logout(request)
    return redirect('home')


def signup_view(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
        return redirect('home')
    else:
        form = RegisterForm()
        return redirect(request, 'signup.html', {'form':form})


# @api_view(['GET'])
# @permission_classes([AllowAny, ])
# def getUserInfo(request):
#     CODE = request.query_params['code']
#     url = "https://kauth.kakao.com/oauth/token"
#     res = {
#             'grant_type': 'authorization_code',
#             'client_id': SOCIAL_OUTH_CONFIG['KAKAO_REST_API_KEY'],
#             'redirect_url': SOCIAL_OUTH_CONFIG['KAKAO_REDIRECT_URI'],
#             'client_secret': SOCIAL_OUTH_CONFIG['KAKAO_SECRET_KEY'],
#             'code': CODE
#         }
#     headers = {
#         'Content-type': 'application/x-www-form-urlencoded;charset=utf-8'
#     }
#     response = request.post(url, data=res, headers=headers)
#     # 그 이후 부분
#     tokenJson = response.json()
#     userUrl = "https://kapi.kakao.com/v2/user/me" # 유저 정보 조회하는 uri
#     auth = "Bearer "+tokenJson['access_token'] ## 'Bearer '여기에서 띄어쓰기 필수!!
#     HEADER = {
#         "Authorization": auth,
#         "Content-type": "application/x-www-form-urlencoded;charset=utf-8"
#     }
#     res = request.get(userUrl, headers=HEADER)
#     return response(res.text)

# @api_view(['GET'])
# @permission_classes([AllowAny, ])
# def kakaoGetLogin(request):
#     CLIENT_ID = SOCIAL_OUTH_CONFIG
#     REDIRET_URL = SOCIAL_OUTH_CONFIG['KAKAO_REDIRECT_URI']
#         url = "https://kauth.kakao.com/oauth/authorize?response_type=code&client_id={0}&redirect_uri={1}".format(
#             CLIENT_ID, REDIRET_URL)
#         res = redirect(url)
#         return res
