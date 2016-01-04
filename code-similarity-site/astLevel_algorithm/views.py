# coding=utf-8

import os
from threading import Thread

from django import forms
from django.http.response import HttpResponse
from django.shortcuts import render, render_to_response
from django.template.context import RequestContext
from joern.all import JoernSteps

from astLevel_algorithm.models import func_similarity_reports
from astLevel_algorithm.util.algorithm.util import vuln_patch_compare_all, \
    ast_match_info
from diffHandle.models import vulnerability_info
from mysite import settings
from software_manager.util.database_proc import is_db_on


try:
    import cPickle as pickle
except ImportError:
    import pickle

# Create your views here.
class funcs_sel(forms.Form): 
    funcs_sel = forms.ModelChoiceField(label="漏洞函数选择",
                                       queryset=vulnerability_info.objects.filter(is_in_db=True),
                                       empty_label=None)
    
class cal_reports():
    def __init__(self, report):
        self.id = report.report_id
        self.cveid = report.vuln_info.cve_info.cveid
        self.vuln_func = report.vuln_info.vuln_func
        self.vuln_file = os.path.basename(report.vuln_info.vuln_file)
        if report.status == "pending":
            self.match_reports = ""
            self.status = "计算中"
            self.cost = 0
        elif report.status == "vuln_func_not_found":
            self.status = "漏洞函数未找到"
            self.match_reports = ""
            self.cost = 0
        elif report.status == "patched_func_not_found":
            self.status = "补丁函数未找到"
            self.match_reports = ""
            self.cost = 0
        else:
            self.status = "计算完成"
            match_info = pickle.loads(report.match_reports.encode("ascii"))
            if match_info.is_valid():
                if match_info.distinct_type_and_const:
                    self.match_reports += "<p>区分变量类型和常量时匹配</p>"
                if match_info.distinct_type_no_const:
                    self.match_reports += "<p>区分变量类型不区分常量时匹配</p>"
                if match_info.distinct_const_no_type:
                    self.match_reports += "<p>区分常量不区分变量时匹配</p>"
                if match_info.no_type_no_const:
                    self.match_reports += "<p>不区分变量类型和常量时匹配</p>"
            else:
                self.match_reports = "未匹配"
            
            self.cost = report.cost
        
def cal_funcs_similarity(request):
    if request.method == "GET":
        funcs = funcs_sel()
        rs = func_similarity_reports.objects.all()
        reports = []
        for r in rs:
            reports.append(cal_reports(r))
            
        return render_to_response("ast_function_level.html",
                                  RequestContext(request, {'funcs':funcs, 'reports':reports}))
    else:
        sel = int(request.POST['funcs_sel'])
        try:
            vuln_info = vulnerability_info.objects.get(vuln_id=sel)
            func_similarity_reports.objects.get(vuln_info=vuln_info)
            return HttpResponse("已经计算过该函数")
        except func_similarity_reports.DoesNotExist:
            if os.path.isdir(os.path.join(settings.NEO4J_DATABASE_PATH, "vuln_db", "index")):
                if is_db_on():
                    neo4jdb = JoernSteps()
                    try:
                        neo4jdb.setGraphDbURL('http://localhost:7474/db/data/')
                        neo4jdb.connectToDatabase()
                    except:
                        return HttpResponse("连接特征数据库失败，请联系管理员查明原因!")
                    
                    th = Thread(target=vuln_patch_compare_all, args=(neo4jdb))
                    th.start()
                    return HttpResponse("启动线程计算中，请稍后查看！")
                    '''
                    vuln_patch_compare(sel, neo4jdb)
                    funcs = funcs_sel()
                    rs = func_similarity_reports.objects.all()
                    reports = []
                    for r in rs:
                        reports.append(cal_reports(r))
            
                    return render_to_response("ast_function_level.html",
                                  RequestContext(request, {'funcs':funcs, 'reports':reports}))
                    '''
                else:
                    return HttpResponse("特征数据库未启动，请先启动特征数据库")
            else:
                return HttpResponse("特征数据库不存在")
        
    
