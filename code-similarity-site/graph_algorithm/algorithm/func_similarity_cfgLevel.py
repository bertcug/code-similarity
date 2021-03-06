#coding=utf-8
from joern.all import JoernSteps
from igraph import *
from base import *
from astLevel_algorithm.util.algorithm.util import *
from graph_algorithm.models import cfg_vuln_patch_funcs_report
from diffHandle.models import vulnerability_info
from graph_algorithm.algorithm.base import getFuncFile
from astLevel_algorithm.models import bug_finder_logs

def translateCFG(db,func_name):
    #get function id
    func_id = getFuncId(db, func_name)
    #get nodes
    cfgNodes = getNodes(db, func_id)
    #get edges
    cfgEdges = getCFGEdges(db, func_id)
    #create igraph cfg
    g = Graph(directed = True)
    #add node and node properties
    for cfgNode in cfgNodes :
        node_prop = {'code':cfgNode.properties['code'],'type':cfgNode.properties['type']}
        g.add_vertex(str(cfgNode._id),**node_prop)
    #add edge and edge properties
    for cfgEdge in cfgEdges :
        startNode = str(cfgEdge.start_node._id)
        endNode = str(cfgEdge.end_node._id)
        edge_prop = {'flowLabel':cfgEdge.properties['flowLabel']}
        g.add_edge(startNode,endNode,**edge_prop)
    return g

def translateCFGById(db,func_id):
	#get nodes
    cfgNodes = getNodes(db, func_id)
    #get edges
    cfgEdges = getCFGEdges(db, func_id)
    #create igraph cfg
    g = Graph(directed = True)
    #add node and node properties
    for cfgNode in cfgNodes :
        node_prop = {'code':cfgNode.properties['code'],'type':cfgNode.properties['type']}
        g.add_vertex(str(cfgNode._id),**node_prop)
    #add edge and edge properties
    for cfgEdge in cfgEdges :
        startNode = str(cfgEdge.start_node._id)
        endNode = str(cfgEdge.end_node._id)
        edge_prop = {'flowLabel':cfgEdge.properties['flowLabel']}
        g.add_edge(startNode,endNode,**edge_prop)
    return g


def node_compat_fn(g1,g2,n1,n2):
    if g1.vs[n1]['type']==g2.vs[n2]['type'] :
        return True
    else:
        return False

def edge_compat_fn(g1,g2,e1,e2):
    if g1.es[e1]['flowLabel'] == g2.es[e2]['flowLabel'] :
        return True
    else:
        return False
    
def cal_similarity(srcCFG,tarCFG,vertexMap):
    count = 0
    sum = 0
    if vertexMap:
        sum = len(vertexMap)
    for i in range(sum) :
        if srcCFG.vs[vertexMap[i]]['code'] == tarCFG.vs[i]['code'] :
            count +=1
    return round((float(count)/float(sum)), 2)

def func_similarity_cfgLevel_proc(soft, db1, db2, vuln_infos):
    allFuncs = getAllFuncs(db1)
    
    for vuln in vuln_infos:
        info = vulnerability_info.objects.get(vuln_id=int(vuln))
        try:
            bug_finder_logs.objects.get(algorithm_type="CFG", target_soft=soft, target_vuln=info)
            continue
        except bug_finder_logs.DoesNotExist:
            pass
            
        func_name = info.cve_info.cveid.replace(u"-", u"_").upper() + u"_VULN_" + info.vuln_func
        
        #获取过滤后的待比对函数集
        ast_root = getASTRootNodeByName(func_name, db2)
        retType = getFuncRetType(ast_root,db2)
        paramList = getFuncParamList(ast_root,db2)
        funcList = filterFuncs(db1,allFuncs,retType,paramList)
        func_node = getFuncNode(func_name, db2)
        
        report_list=[]
        #逐个计算
        for func in funcList:
            flag, simi = func_cfg_similarity(func, db1, func_node, db2)
            if flag:
                report = {"func_name":func.properties["name"], "match":flag, "simi_rate":simi}
                func_file = getFuncFile(db1, func)[len(soft.sourcecodepath):]
                report["func_file":func_file]
                report_list.append(report)
                
        #形成报告,写入数据库
        log = bug_finder_logs()
        log.algorithm_type = "CFG"
        log.target_soft = soft
        log.target_vuln = vuln
        log.cal_report = pickle.dumps(report_list)
        log.save()
   
    
def func_cfg_similarity(func1, db1, func2, db2):
    srcCFG = translateCFGById(db1, func1._id)
    targetCFG = translateCFGById(db2, func2._id)
    ret = srcCFG.get_subisomorphisms_vf2(other = targetCFG,node_compat_fn = node_compat_fn,
                                         edge_compat_fn = edge_compat_fn)
    if len(ret) == 0:
        return False, 0
    else:
        rs = []
        for r in ret:
            rs.append(cal_similarity(srcCFG, targetCFG, r))
        
        return True, round(max(rs), 4)

def func_cfg_similarity_proc(vuln_id, neo4jdb):
    start_time = time.time()
    
    vuln_info = vulnerability_info.objects.get(vuln_id=vuln_id)
    vuln_name = vuln_info.cve_info.cveid.replace(u"-", u"_").upper() + u"_VULN_" + vuln_info.vuln_func
    patch_name = vuln_info.cve_info.cveid.replace(u"-", u"_").upper() + u"_PATCHED_" + vuln_info.vuln_func
    
    report = cfg_vuln_patch_funcs_report()
    report.vuln_info = vuln_info
    report.status = u"pending"
    report.save()
    
    vuln_func = getFuncNode(vuln_name, neo4jdb)
    if vuln_func is None:
        report.status = u"vuln_func_not_found"
        report.save()
        
    patch_func = getFuncNode(patch_name, neo4jdb)
    if patch_name is None:
        report.status = u"patch_func_not_found"
        report.save()
        
    match, simi = func_cfg_similarity(vuln_func, neo4jdb, patch_func, neo4jdb)
    report.is_match = match
    report.similarity_rate = simi
    report.status = u"success"
    end_time = time.time()
    report.cost = round(end_time - start_time, 2)
    report.save()
