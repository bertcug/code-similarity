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
    