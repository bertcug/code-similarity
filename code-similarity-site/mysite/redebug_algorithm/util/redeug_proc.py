#coding=utf-8
'''
Created on Sep 18, 2015

@author: bert
'''
from . import redebug
from redebug_algorithm.models import redebug_reports
from software_manager.models import softwares
from diffHandle.models import cve_infos

def proc_func(soft_id, diff_id):
    #bedore calculate
    soft = softwares.objects.get(software_id = soft_id)
    diff = cve_infos.objects.get(info_id = diff_id)
    report = redebug_reports(diff_id=diff, soft_id=soft)
    report.save()
    
    #calculate
    sourcecodepath = softwares.objects.get(software_id = soft_id).sourcecodepath
    diff_file = cve_infos.objects.get(info_id = diff_id).diff_file
    pattern, match, exact_match, html, cost = redebug.redebug(diff_file, sourcecodepath)
    
    #after
    report.paterns = pattern
    report.matches = match
    report.exact_nmatch = exact_match
    if match:
        report.html_report = html
    report.cost = round(cost, 2)
    report.status = "success"
    report.save()
    