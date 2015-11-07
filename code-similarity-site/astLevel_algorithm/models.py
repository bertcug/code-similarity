# coding=utf-8
from django.db import models
from software_manager.models import softwares
from diffHandle.models import vulnerability_info

# Create your models here.

class func_similarity_reports(models.Model):
    report_id = models.AutoField(primary_key=True)
    vuln_info = models.ForeignKey(vulnerability_info)
    match_reports = models.CharField(max_length=256, null=True)
    status = models.CharField(max_length=50, null=True)
    cost = models.FloatField(null=True)
    
    def __str__(self):
        return self.vuln_info.cve_info.cveid
    
class bug_finder_logs(models.Model):
    log_id = models.AutoField(primary_key=True)
    algorithm_type = models.SmallIntegerField("使用的算法", null=True) #计算的算法,AST->0 CFG->1 PDG->2 三选一
    target_soft = models.ForeignKey(softwares, null=True) 
    target_vuln = models.ForeignKey(vulnerability_info, null=True)
    cal_report = models.TextField("查找报告", null=True)
    
    class Meta:
        db_table="bug_finder_logs"
    