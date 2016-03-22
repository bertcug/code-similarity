#coding=utf-8

'''
Created on Oct 8, 2015

@author: bert
'''

from . import views
from django.conf.urls import include, url

urlpatterns = [
               url(r"^func_similarity$", views.cal_funcs_similarity),
               
               ]