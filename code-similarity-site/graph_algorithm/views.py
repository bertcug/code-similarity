#coding=utf-8

from django.shortcuts import render, render_to_response
from astLevel_algorithm.views import funcs_sel
from django.contrib.auth.decorators import login_required
from django.template.context import RequestContext
from diffHandle.models import vulnerability_info
from graph_algorithm.models import cfg_vuln_patch_funcs_report, pdg_vuln_patch_funcs_report
from django.http.response import HttpResponse
import os
from mysite import settings
from software_manager.util.database_proc import is_character_db_on
from joern.all import JoernSteps
from threading import Thread
from algorithm.func_similarity_cfgLevel import func_cfg_similarity_proc
from algorithm.func_similarity_pdgLevel import func_pdg_similarity_proc
from django import forms
from itertools import chain
from software_manager.models import softwares
from django.db.models import QuerySet
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
                if is_character_db_on():
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
                if is_character_db_on():
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
    software = forms.ModelChoiceField(queryset=softwares.objects.all(), empty_label=None, label="漏洞软件")

def bug_finder_cfg(request):
    if request.method == "GET":
        software_sel = software_sel_form()
        return render_to_response("bug_finder_cfg.html", RequestContext(request, {"software_sel":software_sel}))
    else:
        if request.POST.has_key("sel_vuln"):
            soft_id = int(request.POST.get("software"))
            soft_name = softwares.objects.get(software_id=soft_id).software_name
            softs = softwares.objects.filter(software_name = soft_name)
            cves = []
            for soft in softs:
                cves.extend(soft.cve_infos_set.all())
                
            sel_vuln = vulnerability_info.objects.filter(cve_info__in = cves, is_in_db=True)
            
            software_sel = software_sel_form(request.POST)
            
            return render_to_response("bug_finder_cfg.html", 
                                      RequestContext(request, {"sel_vuln":sel_vuln,"software_sel":software_sel}))
            
        elif request.POST.has_key("find"):
            if not is_character_db_on():
                return HttpResponse(u"特征数据库未启动，请先启动特征数据库")
            
            l = request.POST.getlist("vuln_infos")
            
            
            
            
            