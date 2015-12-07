#coding=utf-8
'''
Created on Oct 3, 2015

@author: bert
'''
import os
from mysite import settings
from VunlsGener import vunlGener
from PatchedGener import patchedGener

def handle_diff_file(vuln):
    vuln_dir = os.path.join(settings.VULN_FUNC_PATH, vuln.cve_info.cveid)
    patch_dir = os.path.join(settings.PATCHED_FUNC_PATH, vuln.cve_info.cveid)
    if not os.path.isdir(vuln_dir):
        os.makedirs(vuln_dir)
    if not os.path.isdir(patch_dir):
        os.makedirs(patch_dir)
            
    vuln_func_src = vunlGener(vuln.cve_info.cveid,
                              vuln.cve_info.vuln_soft.sourcecodepath,
                              vuln.cve_info.diff_file,
                              vuln.vuln_file,
                              vuln.vuln_func,
                              vuln_dir)
    
    if vuln_func_src == "NO_FUNCTION_FOUND" or vuln_func_src == "NO_VULN_FILE_FOUND":
        vuln.vuln_func_source = vuln_func_src
        vuln.patched_func_source = vuln_func_src
        vuln.save()
    else:
        patch_func_src = patchedGener(vuln.cve_info.cveid,
                                      vuln.cve_info.vuln_soft.sourcecodepath,
                                      vuln.cve_info.diff_file,
                                      vuln.vuln_file,
                                      vuln.vuln_func,
                                      patch_dir)
            
        vuln.vuln_func_source = vuln_func_src
        vuln.patched_func_source = patch_func_src
        vuln.save()