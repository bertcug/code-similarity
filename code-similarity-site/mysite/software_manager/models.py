#coding = utf-8
from django.db import models
from django.contrib import auth

# Create your models here.

class softwares(models.Model):
    software_id = models.AutoField(primary_key=True)
    software_name = models.CharField(u"Software name", max_length = 50)
    software_version = models.CharField(u"Software version", max_length = 20)
    sourcecodepath = models.CharField(u"sourcecode path", max_length=200)
    neo4j_db = models.CharField(u"neo4j database path", max_length=200, null = True)
    user = models.ForeignKey(auth.models.User, null = True)
    
    def __str__(self):
        return self.software_name + "-" + self.software_version
        
    class Meta:
        db_table = "softwares"
        ordering = ["software_name", "software_version"]
class graph_dbs(models.Model):
    db_id = models.AutoField(primary_key=True)
    soft = models.ForeignKey(softwares)
    status = models.CharField(max_length = 20)
    port = models.SmallIntegerField(null = True)
    
        
    
