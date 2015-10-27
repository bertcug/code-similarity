# coding=utf-8
'''
Created on 2015年8月31日

@author: Bert
'''
from django.conf.urls import include, url

from diffHandle import views


urlpatterns = {
    url(r'^import_diff/$', views.import_diff, name="import_diff"),
    url(r'^import_vuln/$', views.import_vuln_info, name = "import_vuln_info"),
    url(r'^diff_view/$', views.view_diff, name="diff_view"),
    url(r'view_vuln_func/(?P<vuln_id>[0-9]+)/$', views.read_vuln_func, name="view_vuln_func"),
    url(r'view_patch_func/(?P<vuln_id>[0-9]+)/$', views.read_patch_func, name="view_patch_func"), 
}
