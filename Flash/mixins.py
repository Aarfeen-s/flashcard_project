from .models import UserSession
from django.utils import timezone

class SessionTrackingMixin:
    def create_user_session(self, user_id):
        # First, check if there's already an active session
        active_session = UserSession.objects.filter(
            user_id=str(user_id),
            session_status='active',
            logout_time__isnull=True
        ).first()
        
        if active_session:
            return active_session  # Return existing active session
            
        # If no active session exists, create a new one
        return UserSession.objects.create(
            user_id=str(user_id),
            login_time=timezone.now(),
            session_status='active'
        ) 