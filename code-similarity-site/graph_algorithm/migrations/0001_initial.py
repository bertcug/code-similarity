# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('diffHandle', '0004_vulnerability_info_is_in_db'),
    ]

    operations = [
        migrations.CreateModel(
            name='vuln_patch_funcs_report',
            fields=[
                ('id', models.AutoField(serialize=False, primary_key=True)),
                ('is_match', models.BooleanField()),
                ('similarity_rate', models.FloatField()),
                ('status', models.CharField(max_length=50)),
                ('cost', models.FloatField()),
                ('vuln_info', models.ForeignKey(to='diffHandle.vulnerability_info')),
            ],
        ),
    ]
