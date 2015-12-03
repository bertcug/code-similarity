# coding=utf-8
import os
import time
from util.VunlsGener import getFuncFromSrc
from django import forms
from django.contrib.auth.decorators import login_required
from django.http.response import HttpResponse
from django.shortcuts import render_to_response
from django.template.context import RequestContext
from diffHandle.models import cve_infos, vulnerability_info
from mysite import settings
from software_manager.models import softwares
import hashlib
from diffHandle.util.handle_diff import handle_diff_file
from diffHandle.util.db_funcs import all_in_db, del_all
from threading import Thread
from software_manager.util.database_proc import is_db_on
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage

# Create your views here.
class diff_import(forms.Form):
    cveid = forms.CharField(max_length = 20, label = "CVE编号")
    vuln_soft = forms.ModelChoiceField(queryset=softwares.objects.all(), empty_label=None, label="漏洞软件")
    diff_file = forms.FileField(label="补丁文件")
    
class vuln_info_class(forms.Form):
    cve_id = forms.ModelChoiceField(queryset = cve_infos.objects.all(), empty_label=None, label = "cve编号") 
    vuln_func = forms.CharField(max_length = 100, label = "漏洞函数")
    vuln_func_file = forms.CharField(max_length = 100, label = "漏洞函数存在文件名")
    vuln_type = forms.CharField(max_length=5, label="类型")

@login_required 
def import_diff(request):
    if request.method == "GET":
        diff = diff_import()
        return render_to_response("import_diff.html",\
                                  RequestContext(request, {'diff':diff}))
    else:
        diff = diff_import(request.POST, request.FILES)       
        if diff.is_valid():
            #create cve folder
            tmp_path = os.path.join(settings.DIFF_FILE_PATH, diff.cleaned_data['cveid'].lower())
            if not os.path.isdir(tmp_path):
                os.makedirs(tmp_path)
            
            #upload diff file with time-based file name and get diff file's md5
            file_path = os.path.join(tmp_path, time.time().__str__())
            file_md5 = handle_upload_diff_file(request.FILES['diff_file'], file_path)
            
            #get the releative software
            soft_id = int(request.POST['vuln_soft'])
            soft = softwares.objects.get(software_id = soft_id)
            
            #test whether the infomation has been uploaded
            try:
                obj = cve_infos.objects.get(cveid = diff.cleaned_data['cveid'].lower(),
                                            vuln_soft = soft,
                                            diff_file__endswith = file_md5)
                #the infomation exists, remove the uploaded diff file and tell user
                os.remove(file_path)
                return render_to_response("import_diff.html",
                                          RequestContext(request, {'diff':diff, 'exist':True}))
                
            except cve_infos.DoesNotExist:
                #the information doesn't exists, rename the diff file with md5 and write this into database 
                new_name = os.path.join(tmp_path, file_md5)
                os.rename(file_path, new_name)
                
                obj = cve_infos(cveid = diff.cleaned_data['cveid'].lower(),
                                    vuln_soft = soft,
                                    diff_file = new_name,
                                    user = request.user)
                obj.save()
            
                return HttpResponse(u"录入成功，感谢" + request.user.username + u"对本平台的贡献" )
            
        else:
            return render_to_response("import_diff.html",\
                                      RequestContext(request, {'diff':diff}))
        
def handle_upload_diff_file(diff_file, file_path):
    #upload the diff file
    f = open(file_path, "wb")
    m = hashlib.md5()
    for chunk in diff_file.chunks():
        f.write(chunk)
    
    #calculate the md5
    m.update(open(file_path,"r").read())
    
    return m.hexdigest()

def get_vuln_file(file_name, source_code_dir):
    found_files = []
    for root, dirs, files in os.walk(source_code_dir):
        for _file in files:
            if _file == file_name:
                found_files.append(os.path.abspath(os.path.join(root, _file)))
                break #同目录下不会有同名文件
    return found_files

@login_required           
def import_vuln_info(request):
    if request.method == "GET":
        vuln_info = vuln_info_class()
        return render_to_response("import_vuln.html",\
                                   RequestContext(request, {'vuln_info':vuln_info}))
    else:
        vuln_info = vuln_info_class(request.POST)
        if vuln_info.is_valid():
            _id = int(request.POST['cve_id'])
            cve_info = cve_infos.objects.get(info_id = _id)
            
            #检测漏洞文件位置
            vuln_file = ""
            
            if os.path.isfile(os.path.join(cve_info.vuln_soft.sourcecodepath, 
                                           vuln_info.cleaned_data['vuln_func_file'])):
                #轻松找到
                vuln_file = os.path.join(cve_info.vuln_soft.sourcecodepath, 
                                           vuln_info.cleaned_data['vuln_func_file'])
            else:
                #尝试搜索
                files = get_vuln_file(os.path.basename(vuln_info.cleaned_data['vuln_func_file']),
                                      cve_info.vuln_soft.sourcecodepath)
                #未搜索到
                if len(files) == 0:
                    return render_to_response("import_vuln.html",
                                              RequestContext(request,{'vuln_info':vuln_info, 'no_file_found':True}))
                #成功搜索到
                elif len(files) == 1:
                    vuln_file = files[0]
                    
                #搜索到多个重名文件,
                elif len(files) > 1:
                    return render_to_response("import_vuln.html",
                                              RequestContext(request,{'vuln_info':vuln_info,
                                                                      'multi_file_found':True}))
                
            try:
                obj = vulnerability_info.objects.get(cve_info=cve_info,
                                                    vuln_func = vuln_info.cleaned_data['vuln_func'])
                return render_to_response("import_vuln.html",
                                            RequestContext(request,{'vuln_info':vuln_info,
                                                                    'already':True}))
            except vulnerability_info.DoesNotExist:
                #检测该文件中是否有对应函数
                line_contents = open(vuln_file, 'r').readlines()
                start, end = getFuncFromSrc(line_contents, vuln_info.cleaned_data['vuln_func'])
                if start == -1:
                    return render_to_response("import_vuln.html",
                                              RequestContext(request,{'vuln_info':vuln_info, 'no_func_found':True}))
                else:
                    info = vulnerability_info(cve_info = cve_info,
                                        vuln_func = vuln_info.cleaned_data['vuln_func'],
                                        vuln_file = vuln_file,
                                        vuln_type = vuln_info.cleaned_data['vuln_info'],
                                        user = request.user)
                    info.save()
                    return HttpResponse(u"录入成功，感谢" + request.user.username + u"对本平台的贡献" )
                
        else:
            return render_to_response("import_vuln.html", RequestContext(request,{'vuln_info':vuln_info}))

def get_show_infos(request):
    infos = vulnerability_info.objects.all()
    pages = Paginator(infos,20)
    page = request.GET.get("page")
    show_infos = None
    try:
        show_infos = pages.page(page)
    except PageNotAnInteger:
        show_infos = pages.page(1)
    except EmptyPage:
        show_infos = pages.page(pages.num_pages)
    
    return show_infos
               
@login_required 
def view_diff(request):
    if request.method == "GET":  
        return render_to_response("diff_view.html", RequestContext(request,{'infos':get_show_infos(request)}))
    #处理单个diff
    elif request.POST.has_key('prase_diff'):
        id = request.POST['vuln_id']
        vuln = vulnerability_info.objects.get(vuln_id = id)
        
        handle_diff_file(vuln)

        return render_to_response("diff_view.html",RequestContext(request, {'infos':get_show_infos(request)}))
    #清除所有diff    
    elif request.POST.has_key("clear_all"):
        infos = vulnerability_info.objects.all()
        for info in infos:
            if info.vuln_func_source:
                if os.path.isfile(info.vuln_func_source):
                    os.remove(info.vuln_func_source)
                info.vuln_func_source = ""
            if info.patched_func_source:
                if os.path.isfile(info.patched_func_source):
                    os.remove(info.patched_func_source)
                info.patched_func_source = ""
            info.save()
        
        return render_to_response("diff_view.html",RequestContext(request,{'infos':get_show_infos(request)}))
    #生成所有diff 
    elif request.POST.has_key("make_all"):
        infos = vulnerability_info.objects.all()
        for info in infos:
            if not info.vuln_func_source:
                handle_diff_file(info)
        
        
        return render_to_response("diff_view.html",RequestContext(request,{'infos':get_show_infos(request)}))
    #全部加入特征数据库    
    elif request.POST.has_key("all_in_db"):
        if is_db_on():
            return HttpResponse("特征数据库已启动，请关闭后重试！关闭前请确认无任何使用情况")
        
        th = Thread(target=all_in_db)
        th.start()
        return HttpResponse("生成中，请等候")
    
    #全部删除特征数据库
    elif request.POST.has_key("del_all"):
        if is_db_on():
            return HttpResponse("特征数据库已启动，请关闭后重试！关闭前请确认无任何使用情况")
        
        del_all()
        return HttpResponse("清除完成！")                
        
@login_required      
def read_vuln_func(request, vuln_id):
    _file = open(vulnerability_info.objects.get(vuln_id = vuln_id).vuln_func_source, "r")
    lines = _file.readlines()
    _file.close() 
    return render_to_response("view_code.html", RequestContext(request, {'lines':lines}))

@login_required 
def read_patch_func(request, vuln_id):
    _file = open(vulnerability_info.objects.get(vuln_id = vuln_id).patched_func_source, "r")
    lines = _file.readlines()
    _file.close()
    return render_to_response("view_code.html", RequestContext(request, {'lines':lines}))    
            
