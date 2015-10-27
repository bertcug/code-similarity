from joern.all import JoernSteps
from igraph import *

def getFuncId(j,func_name):
    query_str = 'getFunctionsByName("' + func_name + '").id'
    funcs_id = j.runGremlinQuery(query_str)
    return funcs_id[0]

def getCFGNodes(j,func_id):
    query_str = 'queryNodeIndex("functionId:%s AND isCFGNode:True")' % func_id
    cfgNodes = j.runGremlinQuery(query_str)
    return cfgNodes

def getSymbolNodes(j,func_id):
    query_str = """queryNodeIndex('functionId:%s AND type:Symbol')""" % (func_id)
    symbolNodes = j.runGremlinQuery(query_str)
    return symbolNodes

def getNodes(j,func_id):
    return getCFGNodes(j, func_id)+getSymbolNodes(j, func_id)

def getCFGEdges(j,func_id):
    query_str = """queryNodeIndex('functionId:%s AND isCFGNode:True').outE('FLOWS_TO')""" % func_id
    cfgEdges = j.runGremlinQuery(query_str) 
    return cfgEdges
    
def getDDGEdges(j,func_id):
    query_str = """queryNodeIndex('functionId:%s AND isCFGNode:True').outE('REACHES')""" % (func_id)
    ddgEdges = j.runGremlinQuery(query_str)
    return ddgEdges

def getCDGEdges(j,func_id):
    query_str = """queryNodeIndex('functionId:%s AND isCFGNode:True').outE('CONTROLS')""" % (func_id)
    cdgEdges = j.runGremlinQuery(query_str)
    return cdgEdges

def isNodeExist(g,nodeName) :
    if not g.vs :
        return False
    else:
        return nodeName in g.vs['name']