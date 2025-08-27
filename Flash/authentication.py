from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, AuthenticationFailed
from .models import User
from bson import ObjectId

class CustomJWTAuthentication(JWTAuthentication):
    def get_user(self, validated_token):
        """
        Override to fetch user based on the `user_id` claim, compatible with MongoDB ObjectId.
        """
        try:
            user_id = validated_token.get('user_id')  # Ensure the token includes this claim
            
            if not user_id:
                raise InvalidToken("Token is missing 'user_id' claim.")

            # Convert user_id to ObjectId to match MongoDB _id field
            try:
                user_id = ObjectId(user_id)  # Convert to ObjectId
            except Exception:
                raise InvalidToken("Invalid user_id format. Unable to convert to ObjectId.")
            
            # Lookup user by _id field
            user = User.objects.get(_id=user_id)  # Lookup by the '_id' field in MongoDB
            if not user:
                raise AuthenticationFailed("User not found.")
            
            if not user.is_active:
                raise AuthenticationFailed("User is inactive.")
                
            return user

        except Exception as e:
            raise AuthenticationFailed(f"Authentication failed: {str(e)}")
