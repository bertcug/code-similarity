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
    url(r'^view_vuln_func/(?P<vuln_id>[0-9]+)/$', views.read_vuln_func, name="view_vuln_func"),
    url(r'^view_patch_func/(?P<vuln_id>[0-9]+)/$', views.read_patch_func, name="view_patch_func"),
    url(r"^modify_cve_infos/(?P<info_id>[0-9]+)/$", views.modify_cve_infos, name="modify_cve_infos"),
    url(r"^view_diff_file/(?P<info_id>[0-9]+)/$", views.view_diff_file, name="view_diff_file"),
    url(r"^modify_diff/(?P<info_id>[0-9]+)/$", views.modify_diff, name="modify_diff"),
    url(r"^modify_vuln_info/(?P<vuln_id>[0-9]+)/$", views.modify_vuln_info) 
}
