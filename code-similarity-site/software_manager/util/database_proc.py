#coding=utf-8
'''
Created on Sep 19, 2015

@author: bert
'''
from mysite import settings
from software_manager.models import softwares, graph_dbs
import os
import shutil
import socket

def database_creat_thread(soft_id):
    soft = softwares.objects.get(software_id = soft_id)
    if os.path.isdir(soft.neo4j_db):
        return 
    
    try:
        graph_dbs.objects.get(soft=soft)
    except graph_dbs.DoesNotExist:
    
        source_location = soft.sourcecodepath
        neo4j_location = settings.NEO4J_DATABASE_PATH + \
                soft.software_name + "-" + soft.software_version
        
        cmd_str = "java -jar /home/bert/Documents/joern-0.3.1/bin/joern.jar " + source_location +" -outdir " + neo4j_location
    
        soft.neo4j_db = "pending"
        soft.save()
    
        os.system(cmd_str)
    
        soft.neo4j_db = neo4j_location
        soft.save()
        g = graph_dbs(soft=soft,status="stoped")
        g.save()

def start_neo4j_db(soft_id, port):
    dst_path = os.path.join(settings.TMP_PATH, soft_id.__str__())
    
    if not os.path.isdir(dst_path):
        shutil.copytree(settings.NEO4J_HOME, dst_path)
     
    neo4j_db = softwares.objects.get(software_id=soft_id).neo4j_db
    conf_file = os.path.join(dst_path, "conf/neo4j-server.properties")
    cmd1 = 'sed -i "s#org.neo4j.server.database.location=.*#org.neo4j.server.database.location=' + \
        neo4j_db + '#g" ' + conf_file 
    cmd2 = 'sed -i "s/org.neo4j.server.webserver.port=.*/org.neo4j.server.webserver.port=' + port.__str__() + '/g" ' + conf_file
     
    os.system(cmd1)
    os.system(cmd2)
    
    g = graph_dbs.objects.get(soft=softwares.objects.get(software_id=soft_id))
    g.status = "pending"
    g.save()
    
    start_cmd = os.path.join(dst_path, "bin/neo4j") + " start"
    os.system(start_cmd)
    
    g.status = "started"
    g.port = port
    g.save()
    
def stop_neo4j_db(soft_id):
    dst_path = os.path.join(settings.TMP_PATH, soft_id.__str__())
    cmd_str = os.path.join(dst_path, "bin/neo4j") + " stop"
    os.system(cmd_str)
    shutil.rmtree(dst_path)
    
    g = graph_dbs.objects.get(soft=softwares.objects.get(software_id=soft_id))
    g.status = "stoped"
    g.port = 0
    g.save()

def is_character_db_on():
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    try:
        s.connect(("127.0.0.1",7474))
        s.shutdown(2) 
        return True
    except:
        return False

def start_character_db():
    
    if is_character_db_on():
        return True
    else:
        conf_file = os.path.join(settings.NEO4J_DATABASE_PATH,"neo4j", "conf/neo4j-server.properties")
        cmd1 = 'sed -i "s#org.neo4j.server.database.location=.*#org.neo4j.server.database.location=' + \
            os.path.join(settings.NEO4J_DATABASE_PATH, "vuln_db") + '#g" ' + conf_file 
        cmd2 = 'sed -i "s/org.neo4j.server.webserver.port=.*/org.neo4j.server.webserver.port=7474'\
             + '/g" ' + conf_file
        os.system(cmd1)
        os.system(cmd2)
        start_cmd = os.path.join(settings.NEO4J_DATABASE_PATH,"neo4j","bin/neo4j") + " start"
        os.system(start_cmd)

def stop_character_db():
    if is_character_db_on():   
        stop_cmd = os.path.join(settings.NEO4J_DATABASE_PATH,"neo4j","bin/neo4j") + " stop"
        os.system(stop_cmd)
        return True
    else:
        return True  
    