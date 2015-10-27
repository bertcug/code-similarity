# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('diffHandle', '0004_vulnerability_info_is_in_db'),
        ('astLevel_algorithm', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='func_similarity_reports',
            fields=[
                ('report_id', models.AutoField(serialize=False, primary_key=True)),
                ('match_reports', models.CharField(max_length=256)),
                ('cost', models.FloatField(null=True)),
                ('vuln_infos', models.ForeignKey(to='diffHandle.vulnerability_info')),
            ],
        ),
        migrations.RemoveField(
            model_name='ast_compare_reports',
            name='software_id',
        ),
        migrations.RemoveField(
            model_name='ast_compare_reports',
            name='vuln_infos',
        ),
        migrations.DeleteModel(
            name='ast_compare_reports',
        ),
    ]
