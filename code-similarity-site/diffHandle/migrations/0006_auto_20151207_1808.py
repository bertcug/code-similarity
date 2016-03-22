# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('diffHandle', '0005_vulnerability_info_vuln_type'),
    ]

    operations = [
        migrations.AlterField(
            model_name='vulnerability_info',
            name='vuln_func',
            field=models.CharField(max_length=100, null=True),
        ),
    ]
