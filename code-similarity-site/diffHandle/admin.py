from django.contrib import admin

from diffHandle.models import vulnerability_info, cve_infos

# Register your models here.
admin.site.register(vulnerability_info)
admin.site.register(cve_infos)