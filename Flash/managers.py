from django.contrib.auth.models import BaseUserManager
from bson import ObjectId

class UserManager(BaseUserManager):
    def create_user(self, email, first_name, last_name, password=None):
        if not email:
            raise ValueError("Users must have an email address")
        
        # Normalize email to lowercase
        email = self.normalize_email(email).lower()

        user = self.model(
            email=email,
            first_name=first_name,
            last_name=last_name,
            _id=ObjectId(),
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, first_name, last_name, password=None):
        
        # Normalize email to lowercase
        email = self.normalize_email(email).lower()
        
        user = self.create_user(
            email=email,
            first_name=first_name,
            last_name=last_name,
            password=password,
        )
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user
