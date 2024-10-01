# serializers.py
from rest_framework import serializers
from .models import *

class UserRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['username', 'password']
        extra_kwargs = {
            'password': {'write_only': True}
        }
    
    def create(self, validated_data):
        user = CustomUser.objects.create_user(**validated_data)
        
        # Generate RSA Key Pair
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        import os
        
        # Generate a random encryption password
        encryption_password = os.urandom(16).hex()  # Example password generation
        
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        
        # Encrypt Private Key
        encryption_password_bytes = encryption_password.encode()
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(encryption_password_bytes)
        )
        
        # Convert keys to strings
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        encrypted_private_key_pem = private_key_pem.decode('utf-8')
        
        # Store keys and password
        user.public_key = public_key_pem
        user.encrypted_private_key = encrypted_private_key_pem
        user.save()
        
        return {
            'user': user,
            'encryption_password': encryption_password
        }


class CallRecordingSerializer(serializers.ModelSerializer):
    class Meta:
        model = CallRecording
        fields = ['id', 'user', 'recording_file', 'metadata', 'encrypted', 'created_at']

class ChangeEncryptionPasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)