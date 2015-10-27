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

def getFuncStartFromSrc(line_contents, func_name):
    #现在能处理函数处于一行，处于多行的情况只能解决函数返回值与函数名处于一行的情况
    reg1 = r"[^=]((\s+)|\*)%s(\s*)\(" % func_name #匹配函数及左括号
    reg2 = r"\)(\s*)[^;]" #确定右括号后面没有； 不是函数调用或定义
    reg3 = r"\)(\s*)$;" #函数调用
    
    line_count = len(line_contents)
    for line_num in range(line_count):
        
        line_content = line_contents[line_num]
        # if func_name in line_content and '=' not in line_content:
        
        if re.search(reg1, line_content):
            # 函数名及左侧括号匹配成功
            start = line_num
            for i in range(start, line_count):
                if re.search(reg2, line_contents[i]):
                    return start #找到右括号
                elif re.search(reg3, line_contents[i]):
                    break; #确定为函数调用
    return -1 # 未找到函数入口

def getFuncEndFromSrc(line_contents, func_start):
    func_end = func_start
    brackets = 0
    
    # 默认{ } 不出现在字符串里面
    for line_num in range(func_start, len(line_contents)):
        if "{" in line_contents[line_num]:
            brackets += 1
        if "}" in line_contents[line_num]:
            brackets -= 1
            if brackets == 0:
                func_end = line_num
                break
    
    return func_end
            
# 写入漏洞函数内容
def writeSourceFunc(source_code_file, func_name, vunl_func_file):
    if not os.path.isfile(source_code_file):#上传漏洞信息时出错
        return -2
    
    start_pos = end_pos = 0
    new_func_name = os.path.basename(vunl_func_file)[:-2]
    line_contents = open(source_code_file).readlines()
    
    start_pos = getFuncStartFromSrc(line_contents, func_name)
    if start_pos < 0: #未找到该函数
        return -1
    
    end_pos = getFuncEndFromSrc(line_contents, start_pos) 
    '''
    brackets = 0
    # 默认{ } 不出现在字符串里面
    for line_num in range(start_pos, len(line_contents)):
        if "{" in line_contents[line_num]:
            brackets += 1
        if "}" in line_contents[line_num]:
            brackets -= 1
            if brackets == 0:
                end_pos = line_num
                break
    '''
    write_contents = replace_funcName(func_name, new_func_name, line_contents[start_pos:end_pos + 1])
    # line_contents[start_pos].replace(func_name, new_func_name)
    vunl_file = open(vunl_func_file, 'w')
    vunl_file.writelines(write_contents)
    vunl_file.flush()
    vunl_file.close()
    
    return 0
    
def replace_funcName(old, new, lines):
    # 匹配函数调用（赋值，不赋值）、函数指针赋值
    reg = r"(\s|=)%s(\s*)(\(|\s)" % old
    for i in range(len(lines)):
        if re.search(reg, lines[i]):
            lines[i] = lines[i].replace(old, new)
    return lines
            
