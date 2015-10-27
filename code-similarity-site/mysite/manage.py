#!/usr/bin/env python
import os
import sys
from mysite.settings import make_base_dirs

if __name__ == "__main__":
    make_base_dirs()
    
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mysite.settings")

    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)
