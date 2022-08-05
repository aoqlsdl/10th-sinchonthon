from django.http import JsonResponse
from django.shortcuts import redirect, render, reverse
from django.contrib import messages
import requests
from .models import Accounts
from django.conf import settings

KAKAO_REST_API_KEY = getattr(settings, 'KAKAO_REST_API_KEY', 'KAKAO_REST_API_KEY')
SERECT_KEY = getattr(settings, 'SERECT_KEY','SERECT_KEY' )
import jwt

"""
def index(request):
    message={}
    if 'user' in request.session:
        message['id'] = request.sesstion['user']
    logincheck = {'check':False}
    if request.session.get('access_token'):
        logincheck['check'] = True
    return render(request,'base.html',message,logincheck)
"""   
#1 카카오에서 인가 코드를 받아오는 과정
def kakaoLoginLogic(request):
    restApiKey = KAKAO_REST_API_KEY 
    redirectUrl = 'http://127.0.0.1:8000/kakaoLoginLogicRedirect'
    url = f'https://kauth.kakao.com/oauth/authorize?client_id={restApiKey}&redirect_uri={redirectUrl}&response_type=code'
    return redirect(url) #로그인시 리다이렉트되는 부분

#인가코드를 받아온 것을 바탕으로, 로그인 토큰을 받아오는 과정, 인가코드는 _qs, _url은 토큰 발급요청주소
def kakaoLoginLogicRedirect(request):
    qs = request.GET['code']  #인가코드만 뽑아옴 
    restApiKey = KAKAO_REST_API_KEY 
    redirectUrl = 'http://127.0.0.1:8000/kakaoLoginLogicRedirect'
    tokenUrl = f'https://kauth.kakao.com/oauth/token?grant_type=authorization_code&client_id={restApiKey}&redirect_uri={redirectUrl}&code={qs}'
    
    res = requests.post(tokenUrl) # post로 카카오 API에 토큰 요청
    kakaologinresult = res.json() #json으로 토큰에 대한 응답 받음 
    kakao_access_token = kakaologinresult['access_token'] #access token만 빼먹음

    request.session['access_token'] = kakaologinresult['access_token']
    request.session.modified = True

    #사용자 정보 받아옴
    kakao_user_info = requests.post("https://kapi.kakao.com/v2/user/me", headers={"Authorization" : f"Bearer {kakao_access_token}"},).json()
    kakaoid = kakao_user_info.get('id',None)
    kakaoid = int(kakaoid)
    kakaonickname = kakao_user_info.get('properties')['nickname']

    #단지 세션체크용!
    logincheck = {'check':False}
    if request.session.get('access_token'):
        logincheck['check'] = True
    
    # 카카오에서 불러온 해당 정보를 가지고, 우리 서비스 로그인 시스템에 적용
    if Accounts.objects.filter(user_id=kakaoid).exists(): #지금 접속한 카카오 아이디가 db에존재?
        user = Accounts.objects.get(user_id = kakaoid) #존재하는 카카오 아이디 가진 유저 객체 가져옴
        token = jwt.encode({"user_id":kakaoid}, SERECT_KEY, algorithm='HS256') 
        token = token.decode("utf-8")
        request.session['user']=user.user_id
        return render(request, 'main.html' ,  logincheck)
    else:
        kakao_accounts = Accounts(
            user_id = kakaoid,
            kakao_nickname = kakaonickname,
            token = jwt.encode({"user_id":kakaoid}, SERECT_KEY, algorithm='HS256').decode("utf-8")
        )
        kakao_accounts.save()
        user = Accounts.objects.get(user_id = kakaoid)
        request.session['user'] = user.user_id
        return render(request, 'main.html' ,  logincheck)


def myInformation(request):
    _token = request.session['access_token']
    kakao_user_api = "https://kapi.kakao.com/v2/user/me?access_token="
    kakao_user_api += str(_token)
    user_profile_data = requests.get(kakao_user_api)
    user_json_data = user_profile_data.json()
    user_nickname = user_json_data['properties']['nickname']
    return render(request,'mypage.html',{'nickname' : user_nickname})

def kakaoLogout(request):
    _token = request.session['access_token']
    _url = 'https://kapi.kakao.com/v1/user/logout'
    _header = {
      'Authorization': f'bearer {_token}'
    }
    _res = requests.post(_url, headers=_header)
    _result = _res.json()
    if _result.get('id'):
        del request.session['access_token']
        return render(request, 'main.html')
    else:
        return render(request, 'logoutError.html')



"""
from django.contrib.auth import authenticate, login, logout
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from django.template import loader
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.http import HttpResponse, JsonResponse
from requests import RequestException
from .forms import RegisterForm
import json

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
"""