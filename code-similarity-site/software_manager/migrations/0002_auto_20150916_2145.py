# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('software_manager', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='softwares',
            name='sourcecodepath',
            field=models.CharField(max_length=200, verbose_name='sourcecode path'),
        ),
    ]
