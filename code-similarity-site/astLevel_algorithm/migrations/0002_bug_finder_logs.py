# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('software_manager', '0004_auto_20150930_1528'),
        ('diffHandle', '0004_vulnerability_info_is_in_db'),
        ('astLevel_algorithm', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='bug_finder_logs',
            fields=[
                ('log_id', models.AutoField(serialize=False, primary_key=True)),
                ('algorithm_type', models.SmallIntegerField(null=True, verbose_name=b'\xe4\xbd\xbf\xe7\x94\xa8\xe7\x9a\x84\xe7\xae\x97\xe6\xb3\x95')),
                ('cal_report', models.TextField(null=True, verbose_name=b'\xe6\x9f\xa5\xe6\x89\xbe\xe6\x8a\xa5\xe5\x91\x8a')),
                ('target_soft', models.ForeignKey(to='software_manager.softwares', null=True)),
                ('target_vuln', models.ForeignKey(to='diffHandle.vulnerability_info', null=True)),
            ],
            options={
                'db_table': 'bug_finder_logs',
            },
        ),
    ]
