# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('astLevel_algorithm', '0003_auto_20151008_0917'),
    ]

    operations = [
        migrations.AddField(
            model_name='func_similarity_reports',
            name='status',
            field=models.CharField(max_length=50, null=True),
        ),
        migrations.AlterField(
            model_name='func_similarity_reports',
            name='match_reports',
            field=models.CharField(max_length=256, null=True),
        ),
    ]
