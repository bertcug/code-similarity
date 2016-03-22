# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('diffHandle', '0007_cve_infos_cweid'),
    ]

    operations = [
        migrations.AlterField(
            model_name='cve_infos',
            name='cweid',
            field=models.CharField(default=b'unknown', max_length=20),
        ),
    ]
