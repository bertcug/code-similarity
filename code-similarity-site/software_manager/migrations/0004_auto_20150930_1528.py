# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('software_manager', '0003_graph_dbs'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='softwares',
            options={'ordering': ['software_name', 'software_version']},
        ),
    ]
