"""mysite URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.8/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Add an import:  from blog import urls as blog_urls
    2. Add a URL to urlpatterns:  url(r'^blog/', include(blog_urls))
"""
from django.conf.urls import include, url
from django.contrib import admin
import views
from diffHandle import urls as diff_urls
import software_manager
import redebug_algorithm
import astLevel_algorithm
import graph_algorithm

urlpatterns = [
    url(r'^admin/', include(admin.site.urls)),
    url(r'^$', views.mylogin),
    url(r'^login/', views.mylogin, name="login"),
    url(r'^diffTest/', include(diff_urls, namespace="diff")),
    url(r'^index/$', views.myindex, name="index"),
    
    url(r'^software_manager/', include("software_manager.urls", namespace="software")),
               
    url(r'^algorithm/redebug_algorithm/',include("redebug_algorithm.urls", namespace="redebug_algorithm")),
               
    url(r"^algorithm/ast_level/", include("astLevel_algorithm.urls", namespace="ast")),
               
    url(r"^algorithm/graph/", include("graph_algorithm.urls", namespace="graph")),
]
