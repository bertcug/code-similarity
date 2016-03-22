#coding=utf-8
'''
Created on Jan 4, 2016

@author: root
'''

from algorithm.util import vuln_patch_compare
from astLevel_algorithm.models import vulnerability_info
from joern.all import JoernSteps

if __name__ == "__main__":
    objects = vulnerability_info.objects.all()
    
    neo4jdb = JoernSteps()
    neo4jdb.setGraphDbURL('http://localhost:7474/db/data/')
    neo4jdb.connectToDatabase()
    
    for obj in objects:
        vuln_patch_compare(obj.vuln_id, neo4jdb)