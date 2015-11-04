#coding=utf-8
'''
Created on Oct 9, 2015

@author: bert
'''
import views
from django.conf.urls import url
urlpatterns = {
    url(r"^func_cfg_similarity", views.func_cfg_comp_view),
    url(r"^func_pdg_similarity", views.func_pdg_comp_view),
    url(r"^bug_finder_cfg", views.bug_finder_cfg),
}
