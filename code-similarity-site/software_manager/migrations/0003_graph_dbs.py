# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('software_manager', '0002_auto_20150916_2145'),
    ]

    operations = [
        migrations.CreateModel(
            name='graph_dbs',
            fields=[
                ('db_id', models.AutoField(serialize=False, primary_key=True)),
                ('status', models.CharField(max_length=20)),
                ('port', models.SmallIntegerField(null=True)),
                ('soft', models.ForeignKey(to='software_manager.softwares')),
            ],
        ),
    ]
