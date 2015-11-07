# coding=utf-8
from django import forms
from django.contrib import auth
from django.shortcuts import render_to_response, render
from django.template.context import RequestContext
from django.contrib.auth.decorators import login_required
from django.http.response import HttpResponse, HttpResponseRedirect
from django.core.urlresolvers import reverse
from diffHandle.models import vulnerability_info
import os

class UserForm(forms.Form):
    user = forms.CharField(max_length=20, label=u"用户名")
    passwd = forms.CharField(widget=forms.PasswordInput, max_length=20, label=u"密码")
    
# Create your views here.
def mylogin(request):
    if request.method == "POST":
        user_form = UserForm(request.POST)
        if user_form.is_valid():
            user = user_form.cleaned_data['user']
            passwd = user_form.cleaned_data['passwd']
            
            user = auth.authenticate(username=user, password=passwd)
            if user:
                if user.is_active:
                    auth.login(request, user)
                    if request.GET.has_key("next"):
                        return HttpResponseRedirect(request.GET["next"])
                    else:
                        return HttpResponseRedirect(reverse("index"))
                else:
                    return HttpResponse("该用户已失效,请联系管理员!")
            else:
                user_form = UserForm()
                return render_to_response("login.html", \
                                      RequestContext(request, {'wrong':"用户名或密码错误", 'uf':user_form}))
    else:
        user_form = UserForm()
        return render_to_response("login.html", \
                              RequestContext(request, {'uf':user_form}))

@login_required
def myindex(request):    
    return render_to_response("index.html", RequestContext(request))