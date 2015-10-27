#coding=utf-8
'''
Created on Sep 12, 2015

@author: hust_bert
'''
from django.conf.urls import url
from redebug_algorithm import views

urlpatterns = {
    url(r'^view_all', views.viewall, name="redebug_results"), 
    url(r'^cal_redebug', views.cal_redebug, name="redebug_test"),              
}