# views.py
from rest_framework import generics
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from .serializers import *
from .models import *
import os
from django.conf import settings
from .auth import CookieJWTAuthentication
from django.http import HttpResponse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from io import BytesIO
import base64
from django.core.files.base import ContentFile

class UserRegistrationView(generics.CreateAPIView):
    serializer_class = UserRegistrationSerializer
    
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response({
            'encryption_password': user['encryption_password']
        }, status=status.HTTP_201_CREATED)
class LoginView(generics.GenericAPIView):
    def post(self, request, *args, **kwargs):
        username = request.data.get('username')
        password = request.data.get('password')

        user = authenticate(username=username, password=password)
        if user is not None:
            refresh = RefreshToken.for_user(user)
            response = Response({
                'message': 'Login successful',
            }, status=status.HTTP_200_OK)
            
            # Set the tokens in cookies
            response.set_cookie(
                key='access_token',
                value=str(refresh.access_token),
                httponly=True,
                secure=settings.SESSION_COOKIE_SECURE
            )
            response.set_cookie(
                key='refresh_token',
                value=str(refresh),
                httponly=True,
                secure=settings.SESSION_COOKIE_SECURE
            )
            return response
        
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)


class CallRecordingUploadView(generics.CreateAPIView):
    serializer_class = CallRecordingSerializer
    authentication_class = CookieJWTAuthentication

    def create(self, request, *args, **kwargs):
        try:
            file = request.FILES.get('file')
            if not file:
                return Response({'error': 'No file provided'}, status=status.HTTP_400_BAD_REQUEST)

            metadata = request.data.get('metadata', {})
            user = request.user
            public_key_pem = user.public_key

            aes_key = os.urandom(32)
            iv = os.urandom(16)

            encrypted_aes_key = self.encrypt_aes_key_with_public_key(aes_key, public_key_pem)

            encrypted_file = self.encrypt_file(file, aes_key, iv)

            file_name = file.name if file.name else "default_name.extension"

            call_recording = CallRecording.objects.create(
                user=user,
                recording_file=ContentFile(encrypted_file, name=file_name),
                metadata=metadata,
                encrypted=True,
                encrypted_aes_key=encrypted_aes_key,
                iv=iv
            )

            return Response({'message': "File uploaded successfully"}, status=status.HTTP_201_CREATED)

        except Exception as e:
            print(f"Unexpected error: {str(e)}")
            return Response({'error': 'An error occurred while processing the request'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def encrypt_file(self, file, aes_key, iv):
        try:
            cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_file = encryptor.update(file.read()) + encryptor.finalize()
            return encrypted_file

        except Exception as e:
            print(f"Error during file encryption: {str(e)}")
            raise ValueError('Failed to encrypt the file')

    def encrypt_aes_key_with_public_key(self, aes_key, public_key_pem):
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )

            encrypted_aes_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return base64.b64encode(encrypted_aes_key).decode('utf-8')

        except (ValueError, TypeError) as e:
            print(f"Error during AES key encryption: {str(e)}")
            raise ValueError('Failed to encrypt the AES key, possibly due to invalid public key')

        except Exception as e:
            print(f"Unexpected error during AES key encryption: {str(e)}")
            raise ValueError('An unexpected error occurred during AES key encryption')

class CallRecordingDownloadView(generics.RetrieveAPIView):
    serializer_class = CallRecordingSerializer
    queryset = CallRecording.objects.all()

    def post(self, request, *args, **kwargs):
        try:
            # Get the requested recording object
            recording = self.get_object()

            # Check if the recording is encrypted
            if not recording.encrypted:
                return Response({'error': 'File is not encrypted'}, status=status.HTTP_400_BAD_REQUEST)

            # Get the user's public and encrypted private keys
            user = request.user
            encrypted_private_key_pem = user.encrypted_private_key
            encryption_password = self.request.data.get('encryption_password')  # Retrieve the stored encryption password

            # Decrypt the AES key
            aes_key = self.decrypt_aes_key(recording.encrypted_aes_key, encrypted_private_key_pem, encryption_password)

            # Decrypt the file
            decrypted_file = self.decrypt_file(recording.recording_file, aes_key, recording.iv)

            # Prepare the response for downloading the decrypted file
            response = HttpResponse(decrypted_file.getvalue(), content_type='audio/mpeg')
            response['Content-Disposition'] = f'attachment; filename="{recording.recording_file.name}"'
            return response

        except CallRecording.DoesNotExist:
            # Handle case where the recording doesn't exist
            return Response({'error': 'Recording not found'}, status=status.HTTP_404_NOT_FOUND)

        except ValueError as e:
            # Handle value errors such as incorrect passwords or decryption failures
            return Response({'error': f'Invalid data: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            # General exception handling for unforeseen errors
            print(f"Unexpected error: {str(e)}")
            return Response({'error': 'An error occurred while processing the request'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def decrypt_file(self, file, aes_key, iv):
        try:
            # Set up AES decryption using the provided key and IV
            cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()

            # Decrypt the file content
            decrypted_file = decryptor.update(file.read()) + decryptor.finalize()
            return BytesIO(decrypted_file)

        except Exception as e:
            # Handle decryption errors (invalid file format, corrupted data, etc.)
            print(f"Error during file decryption: {str(e)}")
            raise ValueError('Failed to decrypt the file')

    def decrypt_aes_key(self, encrypted_aes_key, encrypted_private_key_pem, encryption_password):
        try:
            # Decode the AES key from base64
            encrypted_aes_key = base64.b64decode(encrypted_aes_key.encode('utf-8'))
            private_key_pem = encrypted_private_key_pem.encode('utf-8')

            # Decrypt the private key using the encryption password
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=encryption_password.encode(),
                backend=default_backend()
            )

            # Decrypt the AES key using RSA decryption (OAEP padding)
            aes_key = private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return aes_key

        except (ValueError, TypeError) as e:
            # Handle errors related to incorrect password or decryption process
            print(f"Error during AES key decryption: {str(e)}")
            raise ValueError('Failed to decrypt the AES key, possibly due to incorrect encryption password')

        except Exception as e:
            # Catch all other potential errors during decryption
            print(f"Unexpected error during AES key decryption: {str(e)}")
            raise ValueError('An unexpected error occurred during AES key decryption')

class ChangeEncryptionPasswordView(generics.UpdateAPIView):
    serializer_class = ChangeEncryptionPasswordSerializer
    queryset = CustomUser.objects.all()

    def patch(self, request, *args, **kwargs):
        user = request.user
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        old_password = serializer.validated_data['old_password']
        new_password = serializer.validated_data['new_password']

        # Verify the old encryption password and decrypt the existing private key
        old_private_key = self.verify_and_decrypt_private_key(user, old_password)
        if not old_private_key:
            return Response({'error': 'Old password is incorrect'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Re-encrypt the private key with the new password
        new_encryption_password = new_password
        new_private_key_pem = old_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(new_encryption_password.encode())
        )

        # Update the user record with the newly encrypted private key (public key remains unchanged)
        new_encrypted_private_key_pem = new_private_key_pem.decode('utf-8')
        user.encrypted_private_key = new_encrypted_private_key_pem
        user.save()

        return Response({'message': 'Encryption password updated successfully'}, status=status.HTTP_200_OK)

    def verify_and_decrypt_private_key(self, user, old_password):
        try:
            encrypted_private_key_pem = user.encrypted_private_key

            # Convert old password to bytes
            encryption_password_bytes = old_password.encode()

            # Decrypt the old private key with the old password
            private_key = serialization.load_pem_private_key(
                encrypted_private_key_pem.encode('utf-8'),
                password=encryption_password_bytes,
                backend=default_backend()
            )
            return private_key  # Return the decrypted private key
        except Exception as e:
            print(f"Error verifying old password: {str(e)}")
            return None