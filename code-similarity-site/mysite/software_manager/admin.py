from django.contrib import admin
from software_manager.models import softwares, graph_dbs

# Register your models here.
admin.site.register(softwares)
admin.site.register(graph_dbs)
