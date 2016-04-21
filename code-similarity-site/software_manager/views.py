# coding=utf-8
from django.shortcuts import render, render_to_response
from django import forms
from django.template.context import RequestContext
import tarfile
import os

from mysite import settings
from models import softwares, graph_dbs
from django.http.response import HttpResponse
from util.sync_soft import sync_software
from django.contrib.auth.decorators import login_required
from threading import Thread
from util.database_proc import database_creat_thread
from software_manager.util.database_proc import start_neo4j_db, stop_neo4j_db
from software_manager.util.database_proc import start_character_db, stop_character_db, is_db_on
from diffHandle.models import vulnerability_info
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage

# Create your views here.

class soft_info_form(forms.Form):
    soft_name = forms.CharField(label = u"软件名称", max_length = 50)
    soft_version = forms.CharField(label = u"软件版本", max_length = 20)
    source = forms.FileField(label = u"软件源码包(tar.gz)")
    

def untar(file, dir):
    #不能处理目录里有中文的情况,不清楚为什么...
    t = tarfile.open(file, "r:gz")   
    t.extractall(path = dir)
    return dir

def get_show_softs(request):
    softs = softwares.objects.all()
    pages = Paginator(softs, 20)
    page = request.GET.get("page")
    show_softs = None
    try:
        show_softs = pages.page(page)
    except PageNotAnInteger:
        show_softs = pages.page(1)
    except EmptyPage:
        show_softs = pages.page(pages.num_pages)
    
    return show_softs

def software_import(request):
    if request.method == "GET":
        soft = soft_info_form()
        return render_to_response("import_soft.html",
                                  RequestContext(request, {'soft':soft}))
    else:
        soft = soft_info_form(request.POST, request.FILES)
        if soft.is_valid():
            name = soft.cleaned_data['soft_name']
            version = soft.cleaned_data['soft_version']
            file = request.FILES['source']
            
            #upload source to tmp path
            f = open(os.path.join(settings.TMP_PATH, name + version), "wb")
            for chunk in file.chunks():
                f.write(chunk)
            f.close()
            
            # untar the uploaded file
            dir = untar(os.path.join(settings.TMP_PATH, name + version), 
                        os.path.join(settings.SOFTWARE_PATH, name.lower(), name + "-" + version))
            #remove the tmp file
            os.remove(os.path.join(settings.TMP_PATH, name + version))
            
            #save into databases
            software = softwares(software_name = name,
                                 software_version = version,
                                 sourcecodepath = dir,
                                 user = request.user)
            #software.user = request.user
            software.save()
            
            #notify user saved success
            return HttpResponse(u"录入成功，感谢" + request.user.username + u"对我们的支持！")
        else:
            return render_to_response("import_soft.html",
                                  RequestContext(request, {'soft':soft}))

@login_required
def software_show(request):
    if request.method == "GET":
        return render_to_response("show_softs.html", 
                                  RequestContext(request,{"softs":get_show_softs(request)}))
    else:
        if request.POST.has_key('refresh'):   
            return render_to_response("show_softs.html", 
                                      RequestContext(request,{'softs':get_show_softs(request)}))
                                  
        elif request.POST.has_key('sync'):
            infos = sync_software()
            return render_to_response("show_softs.html", 
                                      RequestContext(request, {'softs':get_show_softs(request),'infos':infos}))          
@login_required
def graph_db_show(request):
    if request.method == "GET":
        return render_to_response("graph_database.html",
                                  RequestContext(request, {'softs':get_show_softs(request)}))
    else:
        if request.POST.has_key("create_db"):
            soft_id = int(request.POST['soft_id'])
            th = Thread(target=database_creat_thread, args=(soft_id,))
            th.start()
            
            return HttpResponse(u"已启动线程为该软件生成图形数据库，敬请耐心等待！")
            
def graph_manager(request):
    if request.method == "GET":
        #检测各数据的真实状态,因为如果服务器崩溃,数据库里的状态与真实状态不一致
        infos = graph_dbs.objects.all()
        for info in infos:
            if info.status == "started" and not is_db_on(info.port):
                info.status = "stoped"
                info.port = 0
                info.save()
                       
        status = ""
        obs = vulnerability_info.objects.filter(is_in_db=True)
        if len(obs) > 0:
            if is_db_on():
                status = "ON"
            else:
                status = "OFF"
        else:
            status = "NO_DB"
        return render_to_response("graph_status.html", 
                                  RequestContext(request, {'infos':graph_dbs.objects.all(),'status':status}))
    else:
        if request.POST.has_key('start_db'):
            soft_id = int(request.POST['start'])
            #th = Thread(target=start_neo4j_db, args=(soft_id, 7474+soft_id))
            #th.start()
            
            #端口号为7475-7485
            ports = range(7475,7485)
            inuse_ports = set()
            for port in graph_dbs.objects.values("port"):
                inuse_ports.add(port['port'])
            port = filter(lambda x: not(x in inuse_ports), ports)
            if port is None:
                return HttpResponse(u"端口已全部被占用！")
           
            start_neo4j_db(soft_id, port[0])
            
            infos = graph_dbs.objects.all()
            
            status = ""
            obs = vulnerability_info.objects.filter(is_in_db=True)
            if len(obs) > 0:
                if is_db_on():
                    status = "ON"
                else:
                    status = "OFF"
            else:
                status = "NO_DB"
                
            return render_to_response("graph_status.html", 
                                      RequestContext(request, {'infos':infos,"status":status}))
        elif request.POST.has_key('stop_db'):
            soft_id = int(request.POST['stop']) 
            stop_neo4j_db(soft_id)
            infos = graph_dbs.objects.all()
            
            status = ""
            obs = vulnerability_info.objects.filter(is_in_db=True)
            if len(obs) > 0:
                if is_db_on():
                    status = "ON"
                else:
                    status = "OFF"
            else:
                status = "NO_DB"
                
            return render_to_response("graph_status.html", 
                                      RequestContext(request, {'infos':infos,"status":status}))
        elif request.POST.has_key("start"):
            start_character_db()
            
            infos = graph_dbs.objects.all()
            status = ""
            obs = vulnerability_info.objects.filter(is_in_db=True)
            if len(obs) > 0:
                if is_db_on():
                    status = "ON"
                else:
                    status = "OFF"
            else:
                status = "NO_DB"
                
            return render_to_response("graph_status.html", 
                                      RequestContext(request, {'infos':infos,"status":status}))
        elif request.POST.has_key("shut_down"):
            stop_character_db()
            
            infos = graph_dbs.objects.all()
            status = ""
            obs = vulnerability_info.objects.filter(is_in_db=True)
            if len(obs) > 0:
                if is_db_on():
                    status = "ON"
                else:
                    status = "OFF"
            else:
                status = "NO_DB"
                
            return render_to_response("graph_status.html", 
                                      RequestContext(request, {'infos':infos,"status":status}))
