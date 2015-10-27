# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('astLevel_algorithm', '0002_auto_20151008_0914'),
    ]

    operations = [
        migrations.RenameField(
            model_name='func_similarity_reports',
            old_name='vuln_infos',
            new_name='vuln_info',
        ),
    ]
