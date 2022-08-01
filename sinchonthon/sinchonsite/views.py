from django.shortcuts import render
from requests import request

def main(request):
    return render(request, 'main.html')