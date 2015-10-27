# coding=utf-8
import os
import re
import string

from VunlsGener import getFuncStartFromSrc, getFuncEndFromSrc
from VunlsGener import getSourceCodeFile
from VunlsGener import replace_funcName


def patchedGener(cve_id, soft_folder, diff_file, vunl_file, vunl_func, vunl_func_src, outdir):
    
    if isNormalCondition(diff_file, soft_folder, vunl_file):
        return parseNormalCondition(cve_id, soft_folder, diff_file, vunl_file, vunl_func, outdir)
    else:
        diff_contents = getDiffContents(diff_file, vunl_file)
        patched_file = patchedFileBuild(cve_id, vunl_func, outdir)
        writePatchedFile(cve_id, vunl_func, patched_file, vunl_func_src, diff_contents)
        return patched_file
        
        
# 获得补丁内容
def getDiffContents(diff_file, file_name):
    file_contents = open(diff_file, 'r').readlines()
    line_sum = len(file_contents)
    start_pos = last_pos = 0
    
    for line_num in range(line_sum):
        if file_name in file_contents[line_num]:
            start_pos = line_num
            
    for line_num in range(start_pos, line_sum):
        if file_contents[line_num][0:2] == '@@':
            start_pos = line_num + 1
            break
        
    for line_num in range(start_pos, line_sum):
        if file_contents[line_num][0:2] == '- ' or file_contents[line_num][0:2] == '+ ':
            start_pos = line_num
            break        
    end_pos = line_sum
    for line_num in range(start_pos, line_sum):
        if file_contents[line_num][0:3] == '---' or file_contents[line_num][0:3] == '+++':
            end_pos = line_num - 1
            break
    for line_num in range(start_pos, end_pos):
        if file_contents[line_num][0:2] == '- ' or file_contents[line_num][0:2] == '+ ':
            end_pos = line_num + 1
    diff_contents = file_contents[start_pos:end_pos]
    return diff_contents

# 建立补丁文件
def patchedFileBuild(cve_id, funcName, outdir):
    base_name = cve_id.replace('-', '_').upper()
    return os.path.join(outdir, base_name + "_patched_".upper() + funcName + '.c')

# 打补丁操作
def writePatchedFile(cveid, func_name, patched_file, vunl_func_src, diff_contents):
    diff_sum = len(diff_contents)
    real_diff_contents = []
    # 删除空白行
    for line_num in range(diff_sum):
        if diff_contents[line_num]:
            real_diff_contents.append(diff_contents[line_num])
            
    source_code_contents = open(vunl_func_src, 'r').readlines()
    source_code_sum = len(source_code_contents)
    source_code_num = 0
    diff_num = 0
    tar_contents = []
    while source_code_num < source_code_sum:
        if diff_num < diff_sum:
            if real_diff_contents[diff_num][0] == '-':
                if real_diff_contents[diff_num][1:].strip() in source_code_contents[source_code_num]:
                    diff_num += 1
                    source_code_num += 1
                else:
                    tar_contents.append(source_code_contents[source_code_num])
                    source_code_num += 1
            elif real_diff_contents[diff_num][0] == '+':
                tar_contents.append(real_diff_contents[diff_num][1:])
                diff_num += 1
            elif real_diff_contents[diff_num][0] == ' ':
                if real_diff_contents[diff_num][1:].strip() in source_code_contents[source_code_num]:
                    tar_contents.append(source_code_contents[source_code_num])
                    diff_num += 1
                    source_code_num += 1
                else:
                    tar_contents.append(source_code_contents[source_code_num])
                    source_code_num += 1
            else:
                diff_num += 1
        else:
            tar_contents.append(source_code_contents[source_code_num])
            source_code_num += 1
    file = open(patched_file, 'w')
    
    old = cveid.replace("-", "_").upper() + "_VULN_" + func_name
    new = cveid.replace("-", "_").upper() + "_PATCHED_" + func_name
    replace_funcName(old, new, tar_contents)
    
    file.writelines(tar_contents)
    file.close()
    
def getDiffContentStart(diff_contents, vunl_file):
    lines = []
    line_sum = len(diff_contents)
    reg = r"\+{3}(.*)%s" % vunl_file
    
    start = 0
    for line_num in range(line_sum):
        if re.match(reg, diff_contents[line_num]):
            start = line_num
            break
        
    for i in range(start + 1, line_sum):
        if diff_contents[i][0:2] == '@@':
            lines.append(i)
        elif re.match(r"^(\+|\-)", diff_contents[i]):
            continue
        elif re.match(r"^\s+", diff_contents[i][0:2]):
            continue
        else:
            break
    
    return lines
                 
def isNormalCondition(diff_file, source_folder, vuln_file):
    diff_contents = open(diff_file, "r").readlines()
    src_contents = open(vuln_file, "r").readlines()
    
    start_pos_list = getDiffContentStart(diff_contents, vuln_file)
    if start_pos_list:
        for start_pos in start_pos_list:
            line = getLineNumFromStr(diff_contents[start_pos])
            if line > len(src_contents): #行数不一致，肯定不对应
                return False
            if(diff_contents[start_pos + 1].strip() == src_contents[line - 1].strip()):
                continue
            else:
                return False
            
        return True
    else:
        return False

def getLineNumFromStr(content):
    # 获取开始修改的行号
    start = content.find("-")
    end = content.find(",")
    line = string.atoi(content[start + 1:end])
    return line

def getDiffEnd(diff_contents):
    diff_sum = len(diff_contents)
    diff_bottom = diff_sum
    for i in range(diff_sum):
        if len(diff_contents[diff_sum - i - 1]) < 2:
            continue
        elif diff_contents[diff_sum - i - 1][0:2] == "- " or diff_contents[diff_sum - i - 1][0:2] == "+ ":
            diff_bottom = diff_sum - i + 3
            break
        else:
            continue
    
    return diff_bottom
        
# 处理补丁文件和源文件匹配的情况
def parseNormalCondition(cve_id, soft_folder, diff_file, vunl_file, vunl_func, outdir):
    new_func_name = cve_id.replace("-", "_").upper() + "_PATCHED_" + vunl_func
    diff_contents = open(diff_file, "r").readlines()
    diff_bottom = getDiffEnd(diff_contents)
    
    src_contents = open(vunl_file, "r").readlines()
    
    func_start = getFuncStartFromSrc(src_contents, vunl_func)
    func_end = getFuncEndFromSrc(src_contents, func_start)
    
    
    diff_starts = getDiffContentStart(diff_contents, vunl_file)
    
    # mod_first = getLineNumFromStr(diff_contents[diff_starts[0]])
    # patch_file.writelines(src_contents[func_start:mod_first])
    current_line = func_start
    write_contents = []
    
    for start in diff_starts:
        # start -> @@
        line = getLineNumFromStr(diff_contents[start])
        while current_line < line - 1:
            write_contents.append(src_contents[current_line])
            current_line += 1
       # if current_line < line:
        #    for i in range(current_line, line - 1):
                
          #      current_line = line - 1
                # patch_file.writelines(src_contents[current_line:line])
                     
        for i in range(diff_bottom - start - 1):
            # 删减行
            if diff_contents[start + i + 1][0] == "-":
                content = diff_contents[start + i + 1][1:].strip()
                if(content == src_contents[current_line].strip()):
                    current_line += 1
                    continue
                else:
                    print "Error:diff is not suitable!", cve_id, diff_file, vunl_file, vunl_func
                    print start + i + 1, current_line
            # 添加行
            elif diff_contents[start + i + 1][0] == "+":
                # patch_file.write(src_contents[line + i])
                write_contents.append(diff_contents[start + i + 1][1:])
            elif not isPatchEnd(diff_contents[start + i + 1]):
                if diff_contents[start + i + 1 ].strip() == src_contents[current_line].strip():
                    # patch_file.write(src_contents[line + i])
                    write_contents.append(src_contents[current_line])
                    current_line += 1
                else:
                    print "ERROR: diff_file %d conflicts to src %d" % (start + i, line + i)
            elif isPatchEnd(diff_contents[start + i + 1]):
                break
            else:
                print "ERROR: 未知diff文件类型出现 %s" % diff_file
    
    if current_line <= func_end:
        for i in range(current_line, func_end + 1):
            write_contents.append(src_contents[i])
    
    patch_file = open(os.path.join(outdir, new_func_name + ".c"), "w")
    patch_file.writelines(replace_funcName(vunl_func, new_func_name, write_contents))
    patch_file.close()
    
    return os.path.join(outdir, new_func_name + ".c")

def isPatchEnd(patch_str):
    pattern = r"^[(diff)(index)(@@)]"
    
    if re.match(pattern, patch_str):
        return True
    else:
        return False