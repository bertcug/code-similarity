#coding=utf-8

#author:Jian Zhao

class serializedAST:
    
    variable_maps = {'other':'v'}           #变量与类型映射表
    neo4jdb = None
    data_type_mapping = True
    const_mapping = True
     
    def __init__(self, neo4jdb, data_type_mapping = True, const_mapping = True):
        #@data_type_mapping: True:相同类型变量映射成相同token， False：所有类型变量映射成相同token
        #@const_mapping: True:相同常亮映射到相同token，所有常量映射成相同token
        
        
        #connect to database
        #self.j = JoernSteps()
        #self.j.setGraphDbURL('http://localhost:7474/db/data/')
        #self.j.connectToDatabase()
        
        self.neo4jdb = neo4jdb
        
        self.data_type_mapping = data_type_mapping
        self.const_mapping = const_mapping
        
        
    def getParent(self, node):
        query = "g.v(%d).in('IS_AST_PARENT')" % node._id
        res = self.neo4jdb.runGremlinQuery(query)
        
        #AST树的父节点,要么只有一个,要么没有
        if res:
            return res[0]
        else:
            return None
    
    #处理Identifier节点
    def parseIndentifierNode(self, node):
        parent = self.getParent(node)
        if parent:
            node_type = parent.properties['type']                #根据父节点类型进行判断
            
            if "Callee" == node_type:                            #函数类型
                return ["f(0);", 0]                               #默认Identifier没有子节点
            
            elif "Lable" == node_type:                           #Lable不进行映射
                return ["Identifier(0);", 0]
            
            elif "GotoStatement" == node_type:                   #goto语句的lable也不映射
                return ["Identifier(0);", 0]
            
            else:
                code = node.properties['code']
                var_type = ""
                if self.data_type_mapping:
                    if code in self.variable_maps:
                        var_type = self.variable_maps[code]
                    else:
                        var_type = self.variable_maps['other']
                else:
                    var_type = "v"
                
                return ["%s(0);" % var_type, 0]   
                    
        else:
            print "Error"
            return None
    
    
    #处理ParamList节点,建立参数名与参数类型映射表
    def parseParamListNode(self, node):
        query = "g.v(%d).out('IS_AST_PARENT')" % node._id
        nodes = self.neo4jdb.runGremlinQuery(query)
        
        if nodes:
            for n in nodes:
                variable = self.neo4jdb.runGremlinQuery("g.v(%d).out.filter{it.type == 'Identifier'}.code" % n._id)[0]
                var_type = self.neo4jdb.runGremlinQuery("g.v(%d).out.filter{it.type == 'ParameterType'}.code" % n._id)[0]
                self.variable_maps[variable] = var_type
    
    #处理变量声明语句：
    def parseIdentifierDeclNode(self, node):
        #获取变量名和变量类型
        variable = self.neo4jdb.runGremlinQuery("g.v(%d).out.filter{it.type == 'Identifier'}.code" % node._id)[0]
        var_type = self.neo4jdb.runGremlinQuery("g.v(%d).out.filter{it.type == 'IdentifierDeclType'}.code" % node._id)[0]
        
        self.variable_maps[variable] = var_type

    #处理常量
    def parsePrimaryExprNode(self, node):
        const_code = node.properties['code']
        if self.const_mapping:
            return [const_code + "(0);", 0]
        else:
            return ["c(0);", 0]
        
        
    #类型映射，解决指针与数组、多维数组问题
    def parseType(self, data_type):
        return data_type         #简单处理
           
    
        
    def genSerilizedAST(self, root):
        '''
        @return: a list will be returned, list[0] is the serialized ast string,
                list[1] is the node number of the ast
        @root:  function ast root node
        '''
           
        #AST节点之间以 IS_AST_PARENT 边连接
        query = "g.v(%d).out('IS_AST_PARENT')" % root._id
        res = self.neo4jdb.runGremlinQuery(query)
        
        if res:                                 #如果有子节点
            s_ast = ""                          #存储子节点产生的序列化AST字符串
            num = 0                             #当前节点下所引导节点数
            
            #处理子节点
            for r in res:                       #认为子节点按照childrenNum排序
                
                if(r.properties['type'] == "ReturnType"):
                    continue
                
                if(r.properties['type'] == "ParameterList"):
                    self.parseParamListNode(r)
                    continue
                
                if(r.properties['type'] == "IdentifierDecl"):
                    self.parseIdentifierDeclNode(r)
                    
                ret = self.genSerilizedAST(r)   #递归调用
                s_ast = s_ast + ret[0]          #按照子节点的顺序生成AST序列
                num += ret[1]                   #添加子节点所引导的节点数
                num = num +1                    #将子节点数目也算进去
                                                
            
            #处理根节点
            t = root.properties['type']
            
            if (t == 'AdditiveExpression' or t == 'AndExpression' or t == 'AssignmentExpr'
                or  t == 'BitAndStatement' or t == 'EqualityExpression' or t == 'ExclusiveOrExpression'
                or t == 'InclusiveOrExpression' or t == 'MultiplicativeExpression' 
                or t == 'OrExpression' or t == 'RelationalExpression' or t == 'ShiftStatement'):
                
                s_ast = root.properties['operator'] + "(%d)" % num + ";" + s_ast
            
            else:    
                s_ast = root.properties['type'] + "(%d)" % num + ";" + s_ast                          
            
            return [s_ast, num]                 #返回值是先AST序列，在节点个数，节点个数对后续操作是没用的
        
        else:                                   #处理孤立节点
            num = 0
            t = root.properties['type']
            
            if(t == 'IncDec'):
                s_ast = root.properties['operator'] + "(%d)" % num + ";"
                return [s_ast, num]
            
            if (t == 'CastTarget' or t == 'UnaryOperator'):
                s_ast = root.properties['code'] + "(%d)" % num + ";"
                return [s_ast, num]
            
            if (t == 'SizeofOperand'):
                code = root.properties['code']
                var_type = ""
                
                if self.data_type_mapping:
                    if code in self.variable_maps:
                        var_type = self.variable_maps[code]
                    else:
                        var_type = self.variable_maps['other']
                else:
                    var_type = "v"
                s_ast = var_type + "(%d)" % num + ";"
                
                return [s_ast, num]
            
            if(t == 'Identifier'):
                return self.parseIndentifierNode(root)
            
            if(t == 'PrimaryExpression'):
                return self.parsePrimaryExprNode(root)
                               
            else:
                s_ast = root.properties['type'] + "(%d)" % num + ";"
                return [s_ast, num]
           
