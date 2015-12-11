# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('diffHandle', '0006_auto_20151207_1808'),
    ]

    operations = [
        migrations.AddField(
            model_name='cve_infos',
            name='cweid',
            field=models.CharField(default=b'unknown', max_length=10),
        ),
    ]
