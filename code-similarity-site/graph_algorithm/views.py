#coding=utf-8

from django.shortcuts import render_to_response
from astLevel_algorithm.views import funcs_sel
from django.contrib.auth.decorators import login_required
from django.template.context import RequestContext
from diffHandle.models import vulnerability_info
from graph_algorithm.models import cfg_vuln_patch_funcs_report, pdg_vuln_patch_funcs_report
from django.http.response import HttpResponse
import os
from mysite import settings
from software_manager.util.database_proc import is_db_on
from joern.all import JoernSteps
from threading import Thread
from algorithm.func_similarity_cfgLevel import func_cfg_similarity_proc
from algorithm.func_similarity_pdgLevel import func_pdg_similarity_proc
from django import forms
from software_manager.models import softwares
from software_manager.models import graph_dbs
from graph_algorithm.algorithm.func_similarity_cfgLevel import func_similarity_cfgLevel_proc
from graph_algorithm.algorithm.func_similarity_pdgLevel import func_similarity_pdgLevel_proc 
# Create your views here.

@login_required
def func_cfg_comp_view(request):
    if request.method == "GET":
        funcs = funcs_sel()
        infos = cfg_vuln_patch_funcs_report.objects.all()
        return render_to_response("cfg_comp.html",
                                  RequestContext(request,{"funcs":funcs, "infos":infos}))
    else:
        vuln_id = request.POST.get("funcs_sel")
        try:
            vuln_info = vulnerability_info.objects.get(vuln_id=vuln_id)
            cfg_vuln_patch_funcs_report.objects.get(vuln_info=vuln_info)
            return HttpResponse(u"已经计算过该函数")
        except:
            if os.path.isdir(os.path.join(settings.NEO4J_DATABASE_PATH, "vuln_db", "index")):
                if is_db_on():
                    neo4jdb = JoernSteps()
                    try:
                        neo4jdb.setGraphDbURL('http://localhost:7474/db/data/')
                        neo4jdb.connectToDatabase()
                    except:
                        return HttpResponse(u"连接特征数据库失败，请联系管理员查明原因!")
                    
                    th = Thread(target=func_cfg_similarity_proc, args=(vuln_id, neo4jdb))
                    th.start()
                    return HttpResponse(u"已经启动线程进行计算")
                else:
                    return HttpResponse(u"特征数据库未启动，请先启动特征数据库")
            else:
                return HttpResponse(u"特征数据库不存在")

@login_required
def func_pdg_comp_view(request):
    if request.method == "GET":
        funcs = funcs_sel()
        infos = pdg_vuln_patch_funcs_report.objects.all()
        return render_to_response("pdg_comp.html",
                                  RequestContext(request,{"funcs":funcs, "infos":infos}))
    else:
        vuln_id = request.POST.get("funcs_sel")
        try:
            vuln_info = vulnerability_info.objects.get(vuln_id=vuln_id)
            pdg_vuln_patch_funcs_report.objects.get(vuln_info=vuln_info)
            return HttpResponse(u"已经计算过该函数")
        except:
            if os.path.isdir(os.path.join(settings.NEO4J_DATABASE_PATH, "vuln_db", "index")):
                if is_db_on():
                    neo4jdb = JoernSteps()
                    try:
                        neo4jdb.setGraphDbURL('http://localhost:7474/db/data/')
                        neo4jdb.connectToDatabase()
                    except:
                        return HttpResponse(u"连接特征数据库失败，请联系管理员查明原因!")
                    
                    th = Thread(target=func_pdg_similarity_proc, args=(vuln_id, neo4jdb))
                    th.start()
                    return HttpResponse(u"已经启动线程进行计算")
                else:
                    return HttpResponse(u"特征数据库未启动，请先启动特征数据库")
            else:
                return HttpResponse(u"特征数据库不存在")
        
class software_sel_form(forms.Form):
    software = forms.ModelChoiceField(queryset=softwares.objects.all(),
                                       empty_label=None, label="漏洞软件")

@login_required
def bug_finder(request):
    if request.method == "GET":
        software_sel = software_sel_form()
        return render_to_response("bug_finder.html", RequestContext(request, {"software_sel":software_sel}))
    else:
        if request.POST.has_key("sel_vuln"):
            soft_id = int(request.POST.get("software"))
            soft_name = softwares.objects.get(software_id=soft_id).software_name
            
            #查询当前软件(不含版本)所涉及的所有漏洞函数
            softs = softwares.objects.filter(software_name = soft_name)
            #先查到涉及的所有cve
            cves = []
            for soft in softs:
                cves.extend(soft.cve_infos_set.all())
            
            #查到涉及的所有漏洞    
            sel_vuln = vulnerability_info.objects.filter(cve_info__in = cves, is_in_db=True)
            
            software_sel = software_sel_form(request.POST)
            
            return render_to_response("bug_finder.html", 
                                      RequestContext(request, {"sel_vuln":sel_vuln,"software_sel":software_sel}))
            
        elif request.POST.has_key("find"):
            if not is_db_on():
                return HttpResponse(u"特征数据库未启动，请先启动特征数据库")
            
            soft = softwares.objects.get(software_id=int(request.POST.get("software")))
            try:
                db = graph_dbs.objects.get(soft=soft)
                #检测软件数据库是否启动
                if not is_db_on(db.port):
                    return HttpResponse("软件图形数据库未启动")
                
                #连接软件数据库
                soft_db = JoernSteps()
                try:
                    soft_db.setGraphDbURL("http://localhost:%d/db/data/" % db.port)
                    soft_db.connectToDatabase()
                except:
                    return HttpResponse("连接软件数据库失败! port:%d" % db.port)
                
                #连接特征数据库
                character_db = JoernSteps()
                try:
                    character_db.setGraphDbURL("http://localhost:7474/db/data/")
                    character_db.connectToDatabase()
                except:
                    return HttpResponse("连接特征数据库失败!")
                
                #根据选择使用不同的算法
                alg = request.POST.get("algorithm")
                if alg == "CFG":
                    th = Thread(target=func_similarity_cfgLevel_proc,
                             args=(soft, soft_db, character_db, request.POST.getlist("vuln_infos")))
                    th.start()
                elif alg == "PDG":
                    th = Thread(target=func_similarity_pdgLevel_proc,
                             args=(soft, soft_db, character_db, request.POST.getlist("vuln_infos")))
                    th.start()
                
                return HttpResponse("已启动线程进行计算,请等候!")
            except graph_dbs.DoesNotExist:
                return HttpResponse("软件图形数据库未生成")
           
            
            
            