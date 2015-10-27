# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('software_manager', '0002_auto_20150916_2145'),
        ('diffHandle', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='redebug_reports',
            fields=[
                ('reports_id', models.AutoField(serialize=False, primary_key=True)),
                ('paterns', models.SmallIntegerField(default=0, verbose_name='\u8865\u4e01\u6bb5\u4e2a\u6570')),
                ('matches', models.SmallIntegerField(default=0, verbose_name='\u5339\u914d\u5b57\u6bb5\u4e2a\u6570')),
                ('exact_nmatch', models.SmallIntegerField(default=0, verbose_name='\u51c6\u786e\u5339\u914d\u5b57\u6bb5\u4e2a\u6570')),
                ('cost', models.FloatField(default=0, verbose_name='\u8017\u65f6')),
                ('html_report', models.TextField(null=True, verbose_name='html\u8f93\u51fa')),
                ('status', models.CharField(default=b'pending', max_length=10, verbose_name='\u8ba1\u7b97\u72b6\u6001')),
                ('diff_id', models.ForeignKey(to='diffHandle.cve_infos')),
                ('soft_id', models.ForeignKey(to='software_manager.softwares')),
            ],
            options={
                'db_table': 'redebug_reports',
            },
        ),
    ]
