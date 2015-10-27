# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('software_manager', '0003_graph_dbs'),
        ('diffHandle', '0002_auto_20150929_1521'),
    ]

    operations = [
        migrations.CreateModel(
            name='ast_compare_reports',
            fields=[
                ('report_id', models.AutoField(serialize=False, primary_key=True)),
                ('func_id', models.IntegerField()),
                ('match_reports', models.TextField(null=True)),
                ('cost', models.FloatField(null=True)),
                ('software_id', models.ForeignKey(to='software_manager.softwares')),
                ('vuln_infos', models.ForeignKey(to='diffHandle.vulnerability_info')),
            ],
        ),
    ]
