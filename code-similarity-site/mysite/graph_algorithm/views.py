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
        
    
