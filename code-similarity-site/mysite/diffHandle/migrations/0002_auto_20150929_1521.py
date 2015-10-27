# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('diffHandle', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='vulnerability_info',
            name='vuln_file',
            field=models.CharField(max_length=200),
        ),
    ]
