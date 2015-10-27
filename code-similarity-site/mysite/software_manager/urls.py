#coding=utf-8
'''
Created on Sep 16, 2015

@author: bert
'''
from django.conf.urls import include, url
from . import views

urlpatterns = {
               url(r'^show/$', views.software_show, name="show"),
               url(r'^graphDB/$', views.graph_db_show, name="graphDB"),
               url(r'^graphDB_status/$', views.graph_manager, name="graph_status"),
               }