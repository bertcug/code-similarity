# coding=utf-8
import os
import re


# 生成漏洞函数文件    
def vunlGener(cve_id, soft_folder, diff_file, vuln_file, func_name, outdir):
   
    #source_code_file = getSourceCodeFile(vunl_file, soft_folder)
    vuln_func_src = vunlFileBuild(cve_id, func_name, outdir)
    ret = writeSourceFunc(vuln_file, func_name, vuln_func_src)
    if ret == -1:
        return "NO_FUNCTION_FOUND"
    elif ret == -2:
        return "NO_VULN_FILE_FOUND"
    else:
        return vuln_func_src
               
        
# 找到源码文件
def getSourceCodeFile(file_name, source_code_dir):
    list = os.walk(source_code_dir)
    for root, dirs, files in list:
        for file in files:
            if file == file_name:
                return os.path.join(root, file)
            
# 生成漏洞函数文件的基础名
def vunlFileBuild(cve_id, funcName, outdir):
    base_name = cve_id.replace('-', '_').upper() 
    return os.path.join(outdir, base_name + "_vuln_".upper() + funcName + '.c')

def getFuncFromSrc(line_contents, func_name):
    # @return 返回函数起止行号,未找到返回-1.-1  (从0编号) 
    #先多行匹配,找到函数入口,然后根据换行符个数确定函数入口的行号
    contents = ""
    for line in line_contents:
        contents += line
    
    #在整个文件中正则搜索函数体位置,可以绕过函数的声明
    #pattern = r'^[\w\s]+[\s\*]+%s\s*\([\w\s\*\,\[\]&]*\)\s*\{' % func_name
    #pattern = r'^[\w\s]+[\s\*]+%s\s*\([\s\S]*?\)\s*\{' % func_name
    #pattern = r'^[\w\s]+[\s\*]+%s\s*\([\w\s\*\,\[\]\/&\(\)]*\)\s*\{' % func_name
    #if func_name.startswith('SYSCALL_DEFINE'):
    #   pattern = r'^%s\[\w\s\*\,\[\]\/&\(\)\.{3}]*\)\s*\{' % func_name
    #else:
    pattern = r'^[\w\s]+[\s\*]+%s\s*\([\w\s\*\,\[\]\/&\(\)\.{3}]*\)\s*\{' % func_name
    r_pattern = re.compile(pattern, re.MULTILINE)
    ret = r_pattern.search(contents)
    
    if ret:  #找到该函数,进一步确定函数的起止行
        
        start = 0
        #根据换行符个数确定位置
        for i in range(ret.start()):
            if contents[i] == "\n":
                start += 1
        
        #去掉匹配的多余空行
        for i in range(start, len(line_contents)):
            if re.match(r"^\s+$", line_contents[i]):
                start = i + 1
            else:
                break
        
        #找到结束行
        end = start
        brackets = 0
        for i in range(start, len(line_contents)):
            if "{" in line_contents[i]:
                brackets += line_contents[i].count('{')
            if "}" in line_contents[i]:
                brackets -= line_contents[i].count('}')
                if brackets == 0:
                    end = i
                    break
        
        return start, end
    else:
        return -1, -1   #函数未找到
           
# 写入漏洞函数内容
def writeSourceFunc(source_code_file, func_name, vunl_func_file):
    if not os.path.isfile(source_code_file):#上传漏洞信息时出错
        return -2
    
    #start_pos = end_pos = 0
    new_func_name = os.path.basename(vunl_func_file)[:-2]
    line_contents = open(source_code_file).readlines()
    
    start_pos, end_pos = getFuncFromSrc(line_contents, func_name)
    if start_pos < 0: #未找到该函数
        return -1
    
    write_contents = replace_funcName(func_name, new_func_name, line_contents[start_pos:end_pos + 1])
    # line_contents[start_pos].replace(func_name, new_func_name)
    vunl_file = open(vunl_func_file, 'w')
    vunl_file.writelines(write_contents)
    vunl_file.flush()
    vunl_file.close()
    
    return 0
    
def replace_funcName(old, new, lines):
    # 匹配函数调用（赋值，不赋值）、函数指针赋值
    def str_replace(match_obj):
        return match_obj.group().replace(old, new)
    
    reg_sub = r"[^_A-Za-z0-9]%s[^A-Za-z0-9_]|^%s[^A-Za-z0-9_]" % (old, old)
    for i in range(len(lines)):
        if re.search(reg_sub, lines[i]):
            lines[i] = re.sub(reg_sub, str_replace, lines[i])
            
    return lines
            
