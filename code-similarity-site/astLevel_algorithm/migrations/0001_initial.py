# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('software_manager', '0004_auto_20150930_1528'),
        ('diffHandle', '0004_vulnerability_info_is_in_db'),
    ]

    operations = [
        migrations.CreateModel(
            name='func_similarity_reports',
            fields=[
                ('report_id', models.AutoField(serialize=False, primary_key=True)),
                ('match_reports', models.CharField(max_length=256, null=True)),
                ('status', models.CharField(max_length=50, null=True)),
                ('cost', models.FloatField(null=True)),
                ('vuln_info', models.ForeignKey(to='diffHandle.vulnerability_info')),
            ],
        ),
    ]
