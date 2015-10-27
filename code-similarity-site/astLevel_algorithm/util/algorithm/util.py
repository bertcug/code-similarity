# coding=utf-8
'''
Created on Jul 27, 2015

@author: hust_bert
'''

import time

from SerializedAST import serializedAST
from astLevel_algorithm.models import func_similarity_reports
from diffHandle.models import vulnerability_info
from software_manager.util.database_proc import is_character_db_on, \
    start_character_db


try:
    import cPickle as pickle
except ImportError:
    import pickle
    

class ast_match_info():
    distinct_type_and_const = False  # 区分变量类型和常量的匹配情况
    distinct_type_no_const = False  # 区分变量类型，但不区分常量
    distinct_const_no_type = False  # 区分常量，不区分变量类型
    no_type_no_const = False  # 不区分常量和变量
    
    def is_valid(self):
        return self.distinct_type_and_const or self.distinct_type_no_const or \
            self.distinct_const_no_type or self.no_type_no_const
    
    def get_dict(self):
        return {"distinct_type_and_const":self.distinct_type_and_const,
                "distinct_type_no_const":self.distinct_type_no_const,
                "distinct_const_no_type":self.distinct_const_no_type,
                "no_type_no_const":self.no_type_no_const}
    def __init__(self, member_dict):
        self.distinct_type_and_const = member_dict["distinct_type_and_const"]
        self.distinct_type_no_const = member_dict["distinct_type_no_const"]
        self.distinct_const_no_type = member_dict["distinct_const_no_type"]
        self.no_type_no_const = member_dict["no_type_no_const"]    

def getFuncNode(funcName, neo4jdb):
    query = "getFunctionsByName('%s')" % funcName
    res = neo4jdb.runGremlinQuery(query)
    if res:
        return res[0]
    else:
        return None
    
# get the AST root node
def getASTRootNodeByName(functionName, neo4jdb):
    '''
    @functionName: if it has more than one function named as functionName,
                     only the first one will be return
                        
    Moreover, the corresponding function node is connected to the AST root node 
    by a IS_FUNCTION_OF_AST edge.
    '''
    query = "getFunctionsByName('%s').out('IS_FUNCTION_OF_AST')" % functionName
    res = neo4jdb.runGremlinQuery(query)
    if res:
        return res[0]
    else:
        return None
    
def getFuncRetType(func_ast_node, neo4jdb):
    # @func_ast_node 函数ast树的根结点
    query = "g.v(%d).out('IS_AST_PARENT').filter{it.type == 'ReturnType'}.code" % func_ast_node._id
    res = neo4jdb.runGremlinQuery(query)
    if res:
        return res[0]
    else:
        return None

def getFuncParamList(func_ast_node, neo4jdb):
    # @func_ast_node 函数ast树的根结点
    
    query = "g.v(%d).out('IS_AST_PARENT').filter{it.type == 'ParameterList'}"\
            ".out.filter{it.type == 'Parameter'}.out.filter{it.type == 'ParameterType'}"\
            ".code" % func_ast_node._id
    res = neo4jdb.runGremlinQuery(query)
    if res:
        return res
    else:
        return [u'void']
      
def getAllFuncs(neo4jdb):
    query = "queryNodeIndex('type:Function')"
    return neo4jdb.runGremlinQuery(query)

def filterFuncs(neo4jdb, funcs, return_type, param_list):
    # @neo4jdb 待过滤函数所在数据库
    # @funcs 待过滤函数集合
    # @return_type 目标函数的返回值类型
    # @param_list 目标函数的参数类型列表
    func_list = []
    
    for func in funcs:
        query = "g.v(%d).out('IS_FUNCTION_OF_AST')" % func._id
        func_node = neo4jdb.runGremlinQuery(query)[0]  # 肯定可以找到这个函数，而且唯一
        
        # filter by return type and param list
        ret_type = getFuncRetType(func_node, neo4jdb)
        prm_list = getFuncParamList(func_node, neo4jdb)
        
        if ret_type == return_type and prm_list == param_list:
            func_list.append(func_node)
    
    return func_list    
    
def func_similarity_astLevel(db1, funcs, db2, func_name):
    # @db1 待比对数据库
    # @db2 漏洞特征数据库
    # @func_name 目标函数名
    
    start_time = time.time()
    
    target_func = getASTRootNodeByName(func_name, db2)
    return_type = getFuncRetType(target_func, db2)  # 获取目标函数返回值类型
    param_list = getFuncParamList(target_func, db2)  # 获取目标函数参数类型列表
    
    # funcs = getAllFuncs(db1) #获取所有函数
    filter_funcs = filterFuncs(db1, funcs, return_type, param_list)  # 过滤待比较函数
    
    pattern1 = serializedAST(db2, True, True).genSerilizedAST(target_func)
    pattern2 = serializedAST(db2, False, True).genSerilizedAST(target_func)  # 所有类型变量映射成相同值
    pattern3 = serializedAST(db2, True, False).genSerilizedAST(target_func)
    pattern4 = serializedAST(db2, False, False).genSerilizedAST(target_func)
    
    s1 = serializedAST(db1, True, True)
    s2 = serializedAST(db1, False, True)
    s3 = serializedAST(db1, True, False)
    s4 = serializedAST(db1, False, False)
    
    report_dict = {}
    for func in filter_funcs:
        report = ast_match_info()
        
        if pattern1 == s1.genSerilizedAST(func):
            report.distinct_type_and_const = True
        
        if pattern2 == s2.genSerilizedAST(func):
            report.distinct_const_no_type = True
        
        if pattern3 == s3.genSerilizedAST(func):
            report.distinct_type_no_const = True
        
        if pattern4 == s4.genSerilizedAST(func):
            report.no_type_no_const = True
            
        if report.is_valid():
            report_dict[func] = pickle.dumps(report.get_dict())
    
    end_time = time.time()
    cost = end_time - start_time
    return report_dict, round(cost, 2)

def vuln_patch_compare(vuln_id, neo4jdb):
    vuln_info = vulnerability_info.objects.get(vuln_id=vuln_id)
    vuln_name = vuln_info.cve_info.cveid.replace("-", "_").upper() + "_VULN_" + vuln_info.vuln_func
    patch_name = vuln_info.cve_info.cveid.replace("-", "_").upper() + "_PATCHED_" + vuln_info.vuln_func
    
    # if not is_character_db_on():
    #   start_character_db()
    
    # neo4jdb = JoernSteps()
    # try:
    #    neo4jdb.setGraphDbURL('http://localhost:7474/db/data/')
    #    neo4jdb.connectToDatabase()
    # except:
    start_time = time.time()
    
    report = func_similarity_reports()
    report.vuln_info = vuln_info
    report.status = "pending"
    report.save()
    
    vuln_func = getASTRootNodeByName(vuln_name, neo4jdb)
    if vuln_func is None:
        report.status = "vuln_func_not_found"
        report.save()
        return
    
    patched_func = getASTRootNodeByName(patch_name, neo4jdb)
    if patched_func is None:
        report.status = "patched_func_not_found"
        report.save()
        return
    
    s1 = serializedAST(neo4jdb, True, True)
    s2 = serializedAST(neo4jdb, False, True)
    s3 = serializedAST(neo4jdb, True, False)
    s4 = serializedAST(neo4jdb, False, False)
    
    r = ast_match_info() 
    if s1.genSerilizedAST(vuln_func) == s1.genSerilizedAST(patched_func):
        r.distinct_type_and_const = True
    if s2.genSerilizedAST(vuln_func) == s2.genSerilizedAST(patched_func):
        r.distinct_const_no_type = True
    if s3.genSerilizedAST(vuln_func) == s3.genSerilizedAST(patched_func):
        r.distinct_const_no_type = True
    if s4.genSerilizedAST(vuln_func) == s4.genSerilizedAST(patched_func):
        r.no_type_no_const = True
    
    end_time = time.time()
    
    report.match_reports = pickle.dumps(r)
    report.status = "success"
    report.cost = round(end_time - start_time, 2)
    report.save()
    
def astLevel_similarity_proc():
    pass
