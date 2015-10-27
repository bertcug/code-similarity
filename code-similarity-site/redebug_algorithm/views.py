#coding=utf-8

from django.shortcuts import render, render_to_response
from redebug_algorithm.models import redebug_reports
from django.template.context import RequestContext
from diffHandle.models import vulnerability_info, cve_infos
from django import forms
import string
from util import redebug
from django.http.response import HttpResponse
from software_manager.models import softwares
from threading import Thread
from redebug_algorithm.util.redeug_proc import proc_func

# Create your views here.
        
def viewall(request):
    infos = redebug_reports.objects.all()
    
    return render_to_response("viewall.html",
                              RequestContext(request, {'infos':infos}))
    
class redebug_form(forms.Form):
    soft_sel = forms.ModelChoiceField(label="软件信息", 
                                 queryset=softwares.objects.all(),
                                  empty_label=None)
    diff_sel = forms.ModelChoiceField(label="补丁信息",
                                       queryset=cve_infos.objects.all(),
                                        empty_label=None)
    
def cal_redebug(request):
    if request.method == "GET":
        form = redebug_form()
        return render_to_response("cal_redebug.html",
                                  RequestContext(request, {'form':form}))
    else:
        form = redebug_form(request.POST)
        if form.is_valid():
            soft_id = int(request.POST['soft_sel'])
            diff_id = int(request.POST['diff_sel'])
            
            try: #已经测试过
                redebug_reports.objects.get(diff_id = diff_id, soft_id = soft_id)
                return render_to_response("cal_redebug.html",
                                  RequestContext(request, {'form':form, 'has_cal':True}))
            except redebug_reports.DoesNotExist: # 未测试过
                #启动进程计算
                p = Thread(target=proc_func, args=(soft_id,diff_id))
                p.start()
                
                return HttpResponse("已启动进程进行计算,请稍后转至测试记录汇总界面查看计算结果")
        else:
            return render_to_response("cal_redebug.html",
                                  RequestContext(request, {'form':form}))       