from django.contrib import admin
from .models import CustomUser, CallRecording
# Register your models here.

admin.site.register(CustomUser)
class CallRecordingAdmin(admin.ModelAdmin):
    list_display = ['id','user','recording_file']
admin.site.register(CallRecording,CallRecordingAdmin)