# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='softwares',
            fields=[
                ('software_id', models.AutoField(serialize=False, primary_key=True)),
                ('software_name', models.CharField(max_length=50, verbose_name='Software name')),
                ('software_version', models.CharField(max_length=20, verbose_name='Software version')),
                ('sourcecodepath', models.CharField(max_length=200, verbose_name='source code path')),
                ('neo4j_db', models.CharField(max_length=200, null=True, verbose_name='neo4j database path')),
                ('user', models.ForeignKey(to=settings.AUTH_USER_MODEL, null=True)),
            ],
            options={
                'db_table': 'softwares',
            },
        ),
    ]
