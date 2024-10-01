from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken

class CookieJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        # Check if the cookie contains the token
        token = request.COOKIES.get('access_token')
        if token is None:
            return None
        
        # Verify and decode the token
        try:
            validated_token = self.get_validated_token(token)
        except Exception:
            return None
        
        # Get the user based on the token
        user = self.get_user(validated_token)
        return (user, validated_token)
