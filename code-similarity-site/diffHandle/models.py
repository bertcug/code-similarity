# coding=utf-8
from django.db import models
from django.contrib import auth
from software_manager.models import softwares
import os


class cve_infos(models.Model):
    info_id = models.AutoField(primary_key = True)
    cveid = models.CharField( max_length = 20)
    vuln_soft = models.ForeignKey(softwares)
    diff_file = models.CharField( max_length = 200, null = True)
    user = models.ForeignKey( auth.models.User, null = True)
    
    def __str__(self):
        return self.cveid
    class Meta:
        db_table = "cve_infos"
        ordering = ["cveid"]
      
class vulnerability_info(models.Model):
    vuln_id = models.AutoField(primary_key = True)
    cve_info = models.ForeignKey(cve_infos)
    vuln_func = models.CharField( max_length = 100)
    vuln_file = models.CharField( max_length = 200)
    vuln_type = models.CharField( max_length = 5, null=True )
    vuln_func_source = models.CharField( max_length = 200, null = True)
    patched_func_source = models.CharField( max_length = 200, null = True)
    user = models.ForeignKey(auth.models.User, null = True)
    is_in_db = models.BooleanField(default=False)
    
    def __str__(self):
        return self.cve_info.cveid + ":" + os.path.basename(self.vuln_file) + "[" + self.vuln_func + "]" 
    class Meta:
        db_table = "vulnerability_info"
        ordering = ["cve_info", "vuln_id"]
