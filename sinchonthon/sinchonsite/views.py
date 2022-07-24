
from django.shortcuts import render
from django.http import HttpResponse
from requests import request

def index(request):
    return render(request, 'main.html')
