# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        ('software_manager', '0002_auto_20150916_2145'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='cve_infos',
            fields=[
                ('info_id', models.AutoField(serialize=False, primary_key=True)),
                ('cveid', models.CharField(max_length=20)),
                ('diff_file', models.CharField(max_length=200, null=True)),
                ('user', models.ForeignKey(to=settings.AUTH_USER_MODEL, null=True)),
                ('vuln_soft', models.ForeignKey(to='software_manager.softwares')),
            ],
            options={
                'db_table': 'cve_infos',
            },
        ),
        migrations.CreateModel(
            name='vulnerability_info',
            fields=[
                ('vuln_id', models.AutoField(serialize=False, primary_key=True)),
                ('vuln_func', models.CharField(max_length=100)),
                ('vuln_file', models.CharField(max_length=100)),
                ('vuln_func_source', models.CharField(max_length=200, null=True)),
                ('patched_func_source', models.CharField(max_length=200, null=True)),
                ('cve_info', models.ForeignKey(to='diffHandle.cve_infos')),
                ('user', models.ForeignKey(to=settings.AUTH_USER_MODEL, null=True)),
            ],
            options={
                'db_table': 'vulnerability_info',
            },
        ),
    ]
