#coding=utf-8

from django.db import models
from diffHandle.models import vulnerability_info

# Create your models here.

class cfg_vuln_patch_funcs_report(models.Model):
    id = models.AutoField(primary_key=True)
    vuln_info = models.ForeignKey(vulnerability_info)
    is_match = models.BooleanField(default=False)
    similarity_rate = models.FloatField(null=True)
    status = models.CharField(max_length=50, null=True)
    cost = models.FloatField(null=True)
    
    def __str__(self):
        return self.vuln_info.__str__()

class pdg_vuln_patch_funcs_report(models.Model):
    id = models.AutoField(primary_key=True)
    vuln_info = models.ForeignKey(vulnerability_info)
    is_match = models.BooleanField(default=False)
    similarity_rate = models.FloatField(null=True)
    status = models.CharField(max_length=50, null=True)
    cost = models.FloatField(null=True)
    
    def __str__(self):
        return self.vuln_info.__str__()