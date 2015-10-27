# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('diffHandle', '0002_auto_20150929_1521'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='cve_infos',
            options={'ordering': ['cveid']},
        ),
        migrations.AlterModelOptions(
            name='vulnerability_info',
            options={'ordering': ['cve_info', 'vuln_id']},
        ),
    ]
