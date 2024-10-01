from django.urls import path
from .views import *

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='user-registration'),
    path('login/', LoginView.as_view(), name='login'),
    path('upload/', CallRecordingUploadView.as_view(), name='upload-call-recording'),
    path('download/<int:pk>/', CallRecordingDownloadView.as_view(), name='download-call-recording'),
    path('change-password/', ChangeEncryptionPasswordView.as_view(), name='change-password'),
]