# coding=utf-8
import os
import re
import string

from VunlsGener import getFuncFromSrc
from VunlsGener import replace_funcName


def patchedGener(cve_id, soft_folder, diff_file, vunl_file, vunl_func, outdir):
    real_diff_contents = getRealDiffContents(diff_file, vunl_file)
    patched_file_dir = patchedFileBuild(cve_id, vunl_func, outdir)
    ret = writePatchedFile(cve_id, vunl_func, vunl_file, patched_file_dir, real_diff_contents)
    if ret == -1:
        return "NO_MODIFICATION"
    elif ret == -2:
        return "NO_MATCH"
    else:
        return patched_file_dir
        
        
# 获得real补丁内容
def getRealDiffContents(diff_file, vunl_file):
    diff_contents = open(diff_file, 'r').readlines()
    line_sum = len(diff_contents)
    start_pos = end_pos = 0
    
    reg = r"\+{3}(.*)%s" % os.path.basename(vunl_file)
    for line_num in range(line_sum):
        if re.match(reg, diff_contents[line_num]):
            start_pos = line_num
            break
               
    for line_num in range(start_pos, line_sum):
        if diff_contents[line_num].strip()[0:2] == '@@':
            start_pos = line_num
            break

    for line_num in range(start_pos,line_sum):
        if diff_contents[line_num].startswith(('diff','index','---')):
            end_pos = line_num
            break
        else:
            end_pos = line_sum
       
    real_diff_contents = diff_contents[start_pos:end_pos]
    return real_diff_contents

# 建立补丁文件
def patchedFileBuild(cve_id, funcName, outdir):
    base_name = cve_id.replace('-', '_').upper()
    return os.path.join(outdir, base_name + "_patched_".upper() + funcName + '.c')

# 打补丁操作
def writePatchedFile(cveid, func_name, vuln_file, patched_file_dir, diff_contents):
    diff_ends = []
    tar_lines = []    
    diff_starts = getDiffContentStart(diff_contents, vuln_file)
    diff_lens = len(diff_contents)
    seg_num = len(diff_starts)
    
    if seg_num == 1:
        diff_ends.append(diff_lens-1)
    else:
        for i in range(seg_num-1):
            diff_ends.append(diff_starts[i+1] - 1)
        diff_ends.append(diff_lens-1)
    
    vuln_file_contents = open(vuln_file, 'r').readlines()
    func_start, func_end = getFuncFromSrc(vuln_file_contents, func_name)       
    vuln_func_contents = vuln_file_contents[func_start : func_end+1]
    vuln_file_sum = len(vuln_file_contents)
    vuln_file_num = 0     #num相当于指针，指向vuln_file的行号
    
    #修改后的函数代码
    patched_file = []
        
    for index in range(seg_num):
        part_source = []
        diff_line_num = 1
        for line in diff_contents[diff_starts[index]+1:diff_ends[index]+1]:
            if line.strip().startswith('-'):
                part_source.append(line)
            elif line.strip().startswith('+'):
                continue
            else:
                part_source.append(line)
        for i in range(vuln_file_num,vuln_file_sum-len(part_source)+1):
            if part_source[0].strip() in vuln_file_contents[i]:
                sig = 1
                for p in range(len(part_source)):
                    if not part_source[p].lstrip('-').strip() in vuln_file_contents[i+p]:
                        sig = 0
                        break
                if sig == 1:
                    tar_lines.append(i)
                    break
                else:
                    continue
            else:
                continue
        if len(tar_lines) != index+1:
            return -2
        while diff_line_num < diff_ends[index]-diff_starts[index]+1:
            if vuln_file_num < tar_lines[index]:
                #如果target行号与当前处理的行不一致，说明还未处理到这一行，将当前未修改行写入打补丁后的源码中
                patched_file.append(vuln_file_contents[vuln_file_num])
                vuln_file_num += 1
            else:
                #target行号和当前处理的源码行一致,找到了源码中的对应行
                if diff_contents[diff_starts[index]+diff_line_num][0] == '-':
                    #由于是删除操作，所以处理的行号加1，不将该行写入打补丁后的程序源码中
                    diff_line_num += 1
                    vuln_file_num += 1
                elif diff_contents[diff_starts[index]+diff_line_num][0] == '+':
                    #如果diff行以+开头，说明是对源代码的添加，直接写入打补丁后的函数中，diff处理行号+1
                    patched_file.append(diff_contents[diff_starts[index]+diff_line_num][1:])
                    diff_line_num += 1
                else:
                    #未修改的内容
                    patched_file.append(vuln_file_contents[vuln_file_num])
                    diff_line_num += 1
                    vuln_file_num += 1

    #补丁已经打完，剩下的内容都未修改，直接加入补丁后的源码中
    for i in range(vuln_file_num,vuln_file_sum):
        patched_file.append(vuln_file_contents[i])

    start_pos, end_pos = getFuncFromSrc(patched_file, func_name)
    patched_func = patched_file[start_pos:end_pos + 1]
    
    #检查是否进行了修改
    if patched_func == vuln_func_contents:
        return -1
    
    file = open(patched_file_dir, 'w')
    old = func_name
    new = cveid.replace("-", "_").upper() + "_PATCHED_" + func_name
    replace_funcName(old, new, patched_func)
    
    file.writelines(patched_func)
    file.flush()
    file.close()
    return 0
    
def getDiffContentStart(diff_contents, vunl_file):
    # return @@ segment start number
    startlines = []
    line_sum = len(diff_contents)
    start = 0

    for i in range(start, line_sum):
        if diff_contents[i].strip()[0:2] == '@@':
            startlines.append(i)
        else:
            continue

    return startlines
