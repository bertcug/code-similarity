# coding=utf-8
import os
import re
import string

from VunlsGener import getFuncFromSrc
from VunlsGener import replace_funcName


def patchedGener(cve_id, soft_folder, diff_file, vunl_file, vunl_func, outdir):
    
    if isNormalCondition(diff_file, soft_folder, vunl_file):
        return parseNormalCondition(cve_id, soft_folder, diff_file, vunl_file, vunl_func, outdir)
    else:
        #diff_contents = getDiffContents(diff_file, vunl_file)
        #diff_contents = open(diff_file, "r").readlines()
        real_diff_contents = getRealDiffContents(diff_file, vunl_file)
        patched_file = patchedFileBuild(cve_id, vunl_func, outdir)
        ret = writePatchedFile(cve_id, vunl_func, vunl_file, patched_file, real_diff_contents)
        if ret < 0:
            return "NO_MODIFICATION"
        else:
            return patched_file
        
        
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
        if diff_contents[line_num][0:2] == '@@':
            start_pos = line_num
            break
    '''   
    for line_num in range(start_pos, line_sum):
        if file_contents[line_num][0:2] == '- ' or file_contents[line_num][0:2] == '+ ':
            start_pos = line_num
            break   
    '''
    for line_num in range(start_pos,line_sum):
        if diff_contents[line_num].startswith(('diff','index','---')):
            end_pos = line_num
            break            
    #end_pos = line_sum
    '''
    for line_num in range(start_pos, line_sum):
        if diff_contents[line_num][0:3] == '---' or diff_contents[line_num][0:3] == '+++':
            end_pos = line_num - 1
            break
    for line_num in range(start_pos, end_pos):
        if diff_contents[line_num][0:2] == '- ' or diff_contents[line_num][0:2] == '+ ':
            end_pos = line_num + 1
    '''        
    real_diff_contents = diff_contents[start_pos:end_pos]
    return real_diff_contents

# 建立补丁文件
def patchedFileBuild(cve_id, funcName, outdir):
    base_name = cve_id.replace('-', '_').upper()
    return os.path.join(outdir, base_name + "_patched_".upper() + funcName + '.c')

# 打补丁操作
def writePatchedFile(cveid, func_name, vuln_file, patched_file, diff_contents):
    diff_ends = []
    tar_lines = []    
    diff_starts = getDiffContentStart(diff_contents, vuln_file)
    diff_lens = len(diff_contents)
    seg_num = len(diff_starts)
    
    if seg_num == 1:
        diff_ends.append(diff_lens)
    else:
        for i in range(seg_num-1):
            diff_ends.append(diff_starts[i+1] - 1)
        diff_ends.append(diff_lens)
    
    vuln_file_contents = open(vuln_file, 'r').readlines()
    func_start, func_end = getFuncFromSrc(vuln_file_contents, func_name)       
    vuln_func_contents = vuln_file_contents[func_start : func_end+1]
    vuln_file_sum = len(vuln_file_contents)
    #两个num相当于两个指针，分别指向执行的行号
    vuln_file_num = 0
    
    #修改后的函数代码
    patched_func = []
    patched_file = []
        
    for index in range(seg_num):
        part_source = []
        for line in diff_contents[diff_starts[index]+1:diff_ends[index]]:
            if line.strip().startswith('-'):
                part_source.append(line)
            elif line.strip().startswith('+'):
                continue
            else:
                part_source.append(line)
        for i in range(vuln_file_sum):
            if part_source[0].strip() in vuln_file_contents[i]:
                sig = 1
                for p in range(len(part_source)):
                    if not part_source[p].lstrip('-').strip() in vuln_file_contents[i+p]:
                        sig = 0
                        continue
                if sig == 1:
                    tar_lines.append(i)
                    break
                else:
                    continue
            else:
                continue
        #for diff_line in  diff_contents
        
    '''    
    for start in diff_starts:
        diff_line_num = start + 1
        while diff_line_num < diff_lens:                                 #检查是补丁是否未全部打完
            if diff_contents[diff_line_num][0] == ' ':
                #如果diff文件以空格开头，应该是未修改的内容
                if diff_contents[diff_line_num][1:].strip() in vuln_func_contents[vuln_file_num]:
                    #如果该未修改的内容和当前处理的源码行一致，那么将其添加进打过补丁的函数内容中，处理的行号+1
                    patched_func.append(vuln_func_contents[vuln_file_num])
                    diff_line_num += 1
                    vuln_file_num += 1
                else:
                    #如果该行内容与当前处理的行内容不一致，说明还未处理到这一行，将当前未修改行将阿如打补丁后的源码中
                    patched_func.append(vuln_func_contents[vuln_file_num])
                    vuln_file_num += 1                        
            elif diff_contents[diff_line_num][0] == '-':                   #如果遇到的补丁行以-号开头
                if diff_contents[diff_line_num][1:].strip() in vuln_func_contents[vuln_file_num]:
                    #去除-号之后内容 与 函数当前行的内容一致，那么就是找到了源码中的对应行
                    #由于是删除操作，所以处理的行号加1，不将该行写入打补丁后的程序源码中
                    diff_line_num += 1
                    vuln_file_num += 1
                else:
                    #去除-号后与源码中处理的当前行不一致，那么说明还未到需要修改的地方
                    #也就是说当前的代码是未修改的，所以将其直接加入
                    patched_func.append(vuln_func_contents[vuln_file_num])
                    vuln_file_num += 1
            elif diff_contents[diff_line_num][0] == '+':
                #如果diff行以+开头，说明是对源代码的添加，直接写入打补丁后的函数中，diff处理行号+1
                patched_func.append(diff_contents[diff_line_num][1:])
                diff_line_num += 1
            
            elif isPatchEnd(diff_contents[diff_line_num]):
                break
    '''
    if func_start + vuln_file_num < func_end + 1:
        #补丁已经打完，剩下的内容都未修改，直接加入补丁后的源码中
        patched_func.append(vuln_func_contents[func_start+vuln_file_num:func_end + 1])
    
    patched_func = getFuncFromSrc(patched_file, func_name)
    #检查是否进行了修改
    if patched_func == vuln_func_contents:
        return -1
    
    file = open(patched_file, 'w')
    old = func_name
    new = cveid.replace("-", "_").upper() + "_PATCHED_" + func_name
    replace_funcName(old, new, patched_func)
    
    file.writelines(patched_func)
    file.close()
    return 0
    
def getDiffContentStart(diff_contents, vunl_file):
    # return @@ segment start number
    startlines = []
    line_sum = len(diff_contents)
    reg = r"\+{3}(.*)%s" % os.path.basename(vunl_file)
    
    start = 0
    for line_num in range(line_sum):
        if re.match(reg, diff_contents[line_num]):
            start = line_num
            break
        
    for i in range(start, line_sum):
        if diff_contents[i][0:2] == '@@':
            startlines.append(i)
        elif re.match(r"^(\+|\-)", diff_contents[i]):
            continue
        elif re.match(r"^\s+", diff_contents[i][0:2]):
            continue
        else:
            break
    
    return startlines
                    
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
    
    return min(diff_bottom, diff_sum)
        
# 处理补丁文件和源文件匹配的情况
def parseNormalCondition(cve_id, soft_folder, diff_file, vunl_file, vunl_func, outdir):
    new_func_name = cve_id.replace("-", "_").upper() + "_PATCHED_" + vunl_func
    diff_contents = open(diff_file, "r").readlines()
    diff_bottom = getDiffEnd(diff_contents)
    
    src_contents = open(vunl_file, "r").readlines()
    
    func_start, func_end = getFuncFromSrc(src_contents, vunl_func)
    
    diff_starts = getDiffContentStart(diff_contents, vunl_file)
    
    # mod_first = getLineNumFromStr(diff_contents[diff_starts[0]])
    # patch_file.writelines(src_contents[func_start:mod_first])
    current_line = func_start
    write_contents = []
    
    for start in diff_starts:
        # start -> @@
        line = getLineNumFromStr(diff_contents[start])
        while current_line < line - 1 and current_line <= func_end:
            if current_line < func_start:
                continue
            
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
    
    #检查是否进行了修改
    org_func_contents = src_contents[func_start : func_end+1]
    if org_func_contents == write_contents:
        #未修改，可能是diff文件不对，后者代码bug
        return "NO_MODIFICATION"
        
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