# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('diffHandle', '0004_vulnerability_info_is_in_db'),
        ('graph_algorithm', '0002_auto_20151013_1515'),
    ]

    operations = [
        migrations.CreateModel(
            name='cfg_vuln_patch_funcs_report',
            fields=[
                ('id', models.AutoField(serialize=False, primary_key=True)),
                ('is_match', models.BooleanField(default=False)),
                ('similarity_rate', models.FloatField(null=True)),
                ('status', models.CharField(max_length=50, null=True)),
                ('cost', models.FloatField(null=True)),
                ('vuln_info', models.ForeignKey(to='diffHandle.vulnerability_info')),
            ],
        ),
        migrations.RemoveField(
            model_name='vuln_patch_funcs_report',
            name='vuln_info',
        ),
        migrations.DeleteModel(
            name='vuln_patch_funcs_report',
        ),
    ]
