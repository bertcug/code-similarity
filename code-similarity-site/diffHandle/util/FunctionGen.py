# -*- coding: utf-8 -*-
import re
import linecache
import sys
import os
import string

#读取diff文件内容，创建补丁函数文件与漏洞函数文件
def fileBuild(pFilePath,vFilePath,fileName):
    startPos=0
    filecontent=linecache.getlines(fileName)
    while True:
        startPos=functionBuild(filecontent,startPos,patfile,vulfile)
        #print startPos
        if startPos==len(filecontent):
            break
#从diff文件读取一个函数，分别生成补丁函数与漏洞函数并写入文件
def functionBuild(fileContent,startPos,pFilePath,vFilePath):
    fileContent=fileContent[startPos:]
    for index,item in enumerate(fileContent):
        #print item
        if item.startswith('@@'):
            funcName=re.search(r'[\w_]+\([\w_ &*]+\)',item) 
            #print fileContent
            print 'Get funcName at ' ,startPos+index
            fname=funcName.group(0)
            print fname
            fbody=fBodyBuild(fileContent,index,1)
            writeFile(pFilePath,fname,fbody)
            fbody=fBodyBuild(fileContent,index,0)
            writeFile(vFilePath,fname,fbody)
            return startPos+index+1;
    return len(fileContent)+startPos
#获取函数体
def fBodyBuild(fileContent,startPos,mode):
    funcBody=[]
    fileContent=fileContent[startPos+1:]
    for index,lines in enumerate(fileContent):
        endLine=re.search(r'(diff --|\+\+\+ |--- |@@)',lines)
        if endLine!=None or index==len(fileContent)-1:
            print 'Get funcBody from ',startPos+1,'to',startPos+index,'(relative)'
            #print string.join(fileContent[0:index])
            funcBody=statCompletion(funcBody)#fileContent[0:index])
            return funcBody
        elif mode==1:
            if lines.startswith('-'):
                continue
        if mode==0:
            if lines.startswith('+'):
                continue
        #print 'Append line'
        funcBody.append(lines)
#补全函数体语句
def statCompletion(fileContent):
    beginLine=0
    endLine=0
    flag=0
    for index,item in enumerate(fileContent):      
        if re.search(r'(\+ +|- +)',item)!=None:
            if flag==0:
                beginLine=index;
                flag=1
            endLine=index;
            if item.startswith('+'):             
                fileContent[index]=fileContent[index].replace('+',' ',1)             
            if item.startswith('-'):            
                fileContent[index]=fileContent[index].replace('-',' ',1)
        if re.search(r'(^\+$|^-$)',item)!=None:
            fileContent[index]=fileContent[index].replace('+',' ',1)
    endLine=endLine+1
    print beginLine,endLine
    #print fileContent[beginLine:endLine]
    while beginLine>=1 and re.search(r'.;|.+}|#.',fileContent[beginLine-1])==None:
        beginLine=beginLine-1
    while endLine<len(fileContent) and (re.search(r'.;|.}',fileContent[endLine-1])==None
                                   or (re.search(r'.}',fileContent[endLine])!=None
                                   and string.join(fileContent[beginLine:endLine]).count('{')
                                       >string.join(fileContent[beginLine:endLine]).count('}'))):
        endLine=endLine+1
    #print fileContent[beginLine:endLine]
    return string.join(fileContent[beginLine:endLine])
#写入文件
def writeFile(pFilePath,funcName,funcBody):
    pFilePath.write('void '+funcName+'{\n')
    pFilePath.write(funcBody)
    pFilePath.write('}\n')
    print funcName
    print funcBody

args=sys.argv[1:]
diffFileName=args[0]
#diffFileName='D:\diff2.c'
base = os.path.basename(diffFileName)
dirpath=os.path.dirname(diffFileName)
patfile=open(dirpath+'/'+'patFun'+base,'w')
vulfile=open(dirpath+'/'+'vulFun'+base,'w')
fileBuild(patfile,vulfile,diffFileName)
patfile.close()
vulfile.close()
