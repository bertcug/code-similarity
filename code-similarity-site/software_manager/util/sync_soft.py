#coding=utf-8
'''
Created on Sep 16, 2015

@author: bert
'''
from mysite import settings
import os

from software_manager.models import softwares
from django.contrib.auth.models import User

def travse_one_soft(soft_name, path):
    infos = []
    for file in os.listdir(path):
        # only handle folders
        if not os.path.isdir(os.path.join(path, file)):
            continue
        
        folder = os.path.join(path, file)
           
        soft_version = file.split("-")[1]
        source = os.path.abspath(folder)
            
        try:
            softwares.objects.get(software_name=soft_name, software_version=soft_version)
        except softwares.DoesNotExist:
            user = User.objects.get(username='admin')
            s = softwares(software_name = soft_name,
                            software_version =  soft_version,
                            sourcecodepath =  source,
                            user = user)
            s.save()
            infos.append("Add:" + soft_name + ":" + soft_version + "into databases")
    
    return infos
        
            
def sync_software():
    
    # write new software into databases
    files = os.listdir(settings.SOFTWARE_PATH)
    infos = []
    for file in files:
        if os.path.isdir(os.path.join(settings.SOFTWARE_PATH, file)):
            soft_name = file
            infos.extend(travse_one_soft(soft_name, os.path.join(settings.SOFTWARE_PATH, file)))
    
    #delete old from database
    for soft in softwares.objects.all():
        if not os.path.isdir(soft.sourcecodepath):
            infos.append("Del:" + soft.software_name + ":" + soft.software_version + "from databases")
            soft.delete()
    
    return infos
        
    