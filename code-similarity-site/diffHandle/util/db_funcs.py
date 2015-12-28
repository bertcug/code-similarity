#coding=utf-8

'''
Created on Oct 3, 2015

@author: bert
'''

from diffHandle.models import vulnerability_info
from mysite import settings
import os
import shutil
import time

def all_in_db():
    infos = vulnerability_info.objects.all().filter(is_in_db=False).filter(vuln_func_source__isnull=False)
   
    if not os.path.exists(os.path.join(settings.TMP_PATH, "db_files")):
        os.makedirs(os.path.join(settings.TMP_PATH, "db_files"))
        
    for info in infos:
        if info.vuln_func_source == "NO_FUNCTION_FOUND":
            continue
            
        shutil.copyfile(info.vuln_func_source, os.path.join(settings.TMP_PATH, "db_files", 
                                                            os.path.basename(info.vuln_func_source)))
        if info.patched_func_source == "NO_MODIFICATION":
            continue
        
        shutil.copyfile(info.patched_func_source, os.path.join(settings.TMP_PATH, "db_files",
                                                               os.path.basename(info.patched_func_source)))
        #info.is_in_db = True
        #info.save()
    if not os.path.isdir(os.path.join(settings.NEO4J_DATABASE_PATH, "vuln_db","create_logs")):
        os.makedirs(os.path.join(settings.NEO4J_DATABASE_PATH, "vuln_db","create_logs"))
    log = os.path.join(settings.NEO4J_DATABASE_PATH, "vuln_db","create_logs", time.time().__str__())
    cmd_str = "java -jar " + settings.JOERN_PATH + " "\
                + os.path.join(settings.TMP_PATH, "db_files") + " -outdir "\
                + os.path.join(settings.NEO4J_DATABASE_PATH, "vuln_db") + " >& " + log
    
    os.system(cmd_str)
    shutil.rmtree(os.path.join(settings.TMP_PATH, "db_files"))
    
    s = open(log,"r").readlines()
    logs = [] 
    for log in s:
        logs.append(log.strip("\n"))
    for info in infos:
        vuln = os.path.join(settings.TMP_PATH, "db_files", os.path.basename(info.vuln_func_source))
        patch = os.path.join(settings.TMP_PATH, "db_files", os.path.basename(info.patched_func_source))
        if vuln in logs and (patch in logs or info.patched_func_source == "NO_MODIFICATION"):
            info.is_in_db = True
            info.save()
    
def del_all():
    infos = vulnerability_info.objects.all().filter(is_in_db=True)
    if os.path.exists(os.path.join(settings.NEO4J_DATABASE_PATH, "vuln_db")):
        shutil.rmtree(os.path.join(settings.NEO4J_DATABASE_PATH, "vuln_db"))
        os.makedirs(os.path.join(settings.NEO4J_DATABASE_PATH, "vuln_db", "create_logs"))
    for info in infos:
        info.is_in_db = False
        info.save()