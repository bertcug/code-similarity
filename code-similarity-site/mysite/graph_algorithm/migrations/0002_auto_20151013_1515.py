# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('graph_algorithm', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='vuln_patch_funcs_report',
            name='cost',
            field=models.FloatField(null=True),
        ),
        migrations.AlterField(
            model_name='vuln_patch_funcs_report',
            name='is_match',
            field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name='vuln_patch_funcs_report',
            name='similarity_rate',
            field=models.FloatField(null=True),
        ),
        migrations.AlterField(
            model_name='vuln_patch_funcs_report',
            name='status',
            field=models.CharField(max_length=50, null=True),
        ),
    ]
