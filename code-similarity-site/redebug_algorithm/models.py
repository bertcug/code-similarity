#coding=utf-8
from django.db import models
from django.db.models.fields import SmallIntegerField
from diffHandle.models import cve_infos
from software_manager.models import softwares

# Create your models here.
class redebug_reports(models.Model):
    reports_id = models.AutoField(primary_key = True)
    diff_id = models.ForeignKey(cve_infos) #该记录对应的diff文件路径
    soft_id = models.ForeignKey(softwares) #该记录对应的源码路径
    paterns = models.SmallIntegerField(u"补丁段个数", default = 0)
    matches = models.SmallIntegerField(u"匹配字段个数", default = 0)
    exact_nmatch = models.SmallIntegerField(u"准确匹配字段个数", default = 0)
    cost = models.FloatField(u"耗时", default = 0)
    html_report = models.TextField(u"html输出", null=True)
    status = models.CharField(u"计算状态", max_length=10, default="pending") # pending or success
    
    class Meta:
        db_table = "redebug_reports"