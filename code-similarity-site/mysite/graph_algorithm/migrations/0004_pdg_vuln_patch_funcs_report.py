# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('diffHandle', '0004_vulnerability_info_is_in_db'),
        ('graph_algorithm', '0003_auto_20151014_1646'),
    ]

    operations = [
        migrations.CreateModel(
            name='pdg_vuln_patch_funcs_report',
            fields=[
                ('id', models.AutoField(serialize=False, primary_key=True)),
                ('is_match', models.BooleanField(default=False)),
                ('similarity_rate', models.FloatField(null=True)),
                ('status', models.CharField(max_length=50, null=True)),
                ('cost', models.FloatField(null=True)),
                ('vuln_info', models.ForeignKey(to='diffHandle.vulnerability_info')),
            ],
        ),
    ]
