# models.py
from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomUser(AbstractUser):
    public_key = models.TextField(blank=True, null=True)
    encrypted_private_key = models.TextField(blank=True, null=True)

class CallRecording(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    recording_file = models.FileField(upload_to='call_recordings/')
    metadata = models.JSONField()  # To store metadata like caller details, call times, etc.
    encrypted = models.BooleanField(default=True)  # Whether the recording is encrypted
    encrypted_aes_key = models.TextField(blank=True, null=True)  # Store encrypted AES key
    iv = models.BinaryField(blank=True, null=True)  # Store initialization vector
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Recording by {self.user.username} at {self.created_at}"
    
'''
class CallBound(models.Model):
    callboundid = models.CharField(max_length=255, primary_key=True)
    callboundtype = models.CharField(max_length=255)

    def __str__(self):
        return self.callboundtype


class CallLabel(models.Model):
    labelid = models.AutoField(primary_key=True)
    labelname = models.CharField(max_length=255)

    def __str__(self):
        return self.labelname


class CRStatus(models.Model):
    statusid = models.AutoField(primary_key=True)
    crstatustype = models.CharField(max_length=255)

    def __str__(self):
        return self.crstatustype


class CallRecording(models.Model):
    callid = models.AutoField(primary_key=True)
    calluuid = models.UUIDField(default=uuid.uuid4, editable=False)
    owner = models.IntegerField()
    username = models.CharField(max_length=255)
    callbound = models.ForeignKey(CallBound, on_delete=models.CASCADE)
    datetime = models.DateTimeField()
    calllabel = models.ForeignKey(CallLabel, on_delete=models.CASCADE)
    callrecordingtype = models.CharField(max_length=255)
    crmetadata = models.TextField()
    crmedia = models.BinaryField()
    crstatusid = models.ForeignKey(CRStatus, on_delete=models.CASCADE)

    def __str__(self):
        return f"CallRecording {self.calluuid} by {self.username}"


class Encryption(models.Model):
    encid = models.AutoField(primary_key=True)
    owner = models.CharField(max_length=255)
    username = models.CharField(max_length=255)
    public_key = models.TextField()
    encrypted_private_key = models.TextField()
    encrypted_aes_key = models.TextField()
    iv_key = models.TextField()
    datetime = models.DateTimeField()

    def __str__(self):
        return f"Encryption for {self.username}"
'''