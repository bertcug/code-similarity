#!/usr/bin/env python
import sys
import os
import re
import time
import common
import patchloader
import sourceloader
import reporter

try:
    import argparse
    import magic
except ImportError as err:
    print err
    sys.exit(-1)


def parse_args():
    '''
    Parse command line arguments
    '''
    parser = argparse.ArgumentParser()
    # optional arguments
    parser.add_argument('-n', '--ngram',\
            action='store', dest='ngram_size', type=int, default=4, metavar='NUM',\
            help='use n-gram of NUM lines (default: %(default)s)')
    parser.add_argument('-c', '--context',\
            action='store', dest='context_line', type=int, default=10, metavar='NUM',\
            help='print NUM lines of context (default: %(default)s)')
    parser.add_argument('-v', '--verbose',\
            action='store_true', dest='verbose_mode', default=False,\
            help='enable verbose mode (default: %(default)s)')
    # positional arguments
    parser.add_argument('patch_path', action='store', help='path to patch files (in unified diff format)')
    parser.add_argument('source_path', action='store', help='path to source files')

    try:
        args = parser.parse_args()
        common.ngram_size = args.ngram_size
        common.context_line = args.context_line
        common.verbose_mode = args.verbose_mode
        return args.patch_path, args.source_path
    except IOError, msg:
        parser.error(str(msg))


def redebug(patch_path, source_path):
    # parse arguments
    start_time = time.time()

    # initialize a magic cookie pointer
    common.magic_cookie = magic.open(magic.MAGIC_MIME)
    common.magic_cookie.load()
    
    ret =[]
    # traverse patch files
    patch = patchloader.PatchLoader()
    npatch = patch.traverse(patch_path)
  
    ret.append(npatch)

    # traverse source files
    source = sourceloader.SourceLoader()
    nmatch = source.traverse(source_path, patch)
   
    ret.append(nmatch)

    # generate a report
    report = reporter.Reporter(patch, source)
    exact_nmatch, html = report.output()
    ret.append(exact_nmatch)
    ret.append(html)

    common.magic_cookie.close()
    elapsed_time = time.time() - start_time
    #print '[+] %d matches given %d patches ... %.1fs' % (exact_nmatch, npatch, elapsed_time)
    ret.append(elapsed_time)
    return ret

