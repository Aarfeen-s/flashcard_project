from djongo import models
from djongo.models import ObjectIdField
from bson import ObjectId
from django.shortcuts import get_object_or_404
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.utils.translation import gettext_lazy as _
from rest_framework_simplejwt.tokens import RefreshToken
from .managers import UserManager
from django.utils import timezone
from datetime import timedelta
from django.core.exceptions import ValidationError, ImproperlyConfigured
from django.db import models


class Tag(models.Model):
    name = models.CharField(max_length=50)

    def __str__(self):
        return self.name

from flashapi import settings
class Folder(models.Model):
    name = models.CharField(max_length=255)
    parent = models.ForeignKey('self', null=True, blank=True, on_delete=models.CASCADE, related_name='subfolders')
    type = models.CharField(max_length=50, default='folder')
    created_by = models.CharField(max_length= 50, blank= True)

    # class Meta:
    #     # Ensure folder names are unique per user and optionally within a parent folder
    #     unique_together = ('name', 'created_by', 'parent')

    def __str__(self):
        return self.name

class File(models.Model):
    name = models.CharField(max_length=255)
    folder = models.ForeignKey(Folder, on_delete=models.CASCADE, related_name='files', null=True, blank=True)
    created_by = models.CharField(max_length=100)

    def __str__(self):
        return self.name
class ObjectIdField(models.Field):
    def get_prep_value(self, value):
        if not value:
            return None
        if isinstance(value, ObjectId):
            return str(value)
        return value

    def to_python(self, value):
        if not value:
            return None
        if isinstance(value, ObjectId):
            return value
        return ObjectId(value)

    def from_db_value(self, value, expression, connection):
        if not value:
            return None
        if isinstance(value, ObjectId):
            return value
        return ObjectId(value)

from django.contrib.auth.models import User

class MCQuestion(models.Model):
    
    QUESTION_TYPE_CHOICES = [
        ('MCQ', 'Multiple Choice Question'),
        ('FIB', 'Fill in the Blanks'),
        ('SUB', 'Subjective'),
        ('TRUEFALSE', 'True or False'),
        ('IMAGE', 'Diagram Study'),
    ]
    def generate_object_id():
      return str(ObjectId())

    
    id = models.CharField(primary_key=True, default=generate_object_id, editable=False, max_length=200)
    
    statement = models.CharField(max_length=255)
    created_date = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=255, blank= True)
    question_type = models.CharField(max_length=15, choices=QUESTION_TYPE_CHOICES)
    explanation = models.TextField(blank=True)
    folder = models.ForeignKey(Folder, on_delete=models.CASCADE, related_name='mc_questions', blank=True, null=True)
    tags = models.ManyToManyField(Tag, related_name='mc_questions', blank=True)

    class Meta:
        # Unique constraint for the combination of 'created_by' and 'statement'
        # constraints = [
        #     models.UniqueConstraint(fields=['created_by', 'statement'], name='unique_created_by_statemet')
        # ]
        pass  # Or simply remove the constraints list
   

    def __str__(self):
        return self.statement



class MCQAnswer(models.Model):
    question = models.ForeignKey(MCQuestion, related_name='answers', on_delete=models.CASCADE)
    answer_text = models.CharField(max_length=255)
    is_correct = models.BooleanField(default=False)
    folder = models.ForeignKey(Folder, on_delete=models.CASCADE, related_name='mcq_answers', blank=True, null=True)

    def __str__(self):
        return self.answer_text

class ObjectIdField(models.Field):
    def get_prep_value(self, value):
        if not value:
            return None
        if isinstance(value, ObjectId):
            return str(value)
        return value

    def to_python(self, value):
        if not value:
            return None
        if isinstance(value, ObjectId):
            return value
        return ObjectId(value)

    def from_db_value(self, value, expression, connection):
        if not value:
            return None
        if isinstance(value, ObjectId):
            return value
        return ObjectId(value)

class Question(models.Model):
    QUESTION_TYPE_CHOICES = [
        ('MCQ', 'Multiple Choice Question'),
        ('FIB', 'Fill in the Blanks'),
        ('SUB', 'Subjective'),
        ('TRUEFALSE', 'True or False'),
        ('IMAGE', 'Diagram Study'),
    ]
    statement = models.TextField()
    created_date = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=255)
    question_type = models.CharField(max_length=15, choices=QUESTION_TYPE_CHOICES)  # Adjust max_length as per your needs
    answers = models.TextField()  # Assuming it will store answer choices or answers
    explanation = models.TextField()
    folder = models.ForeignKey(Folder, on_delete=models.CASCADE, related_name='questions', blank=True, null=True)
    tags = models.ManyToManyField(Tag, related_name='questions', blank=True)
    

    class Meta:
        # Unique constraint for the combination of 'created_by' and 'statement'
        # constraints = [
        #     models.UniqueConstraint(fields=['created_by', 'statement'], name='unique_created_by_statement')
        # ]
        pass
    def __str__(self):
        return self.statement

class Answer(models.Model):
    question = models.ForeignKey(Question, related_name='related_answers', on_delete=models.CASCADE)
    answer_text = models.TextField()
    folder = models.ForeignKey(Folder, on_delete=models.CASCADE, related_name='answers', blank=True, null=True)


    def __str__(self):
        return self.answer_text

class FillQuestions(models.Model):
    QUESTION_TYPE_CHOICES = [
        ('MCQ', 'Multiple Choice Question'),
        ('FIB', 'Fill in the Blanks'),
        ('SUB', 'Subjective'),
        ('TRUEFALSE', 'True or False'),
        ('IMAGE', 'Diagram Study'),
    ]
    statement = models.CharField(max_length=255)  # To store the fill in the blanks statement
    created_by = models.EmailField(max_length=100)  # To store the name of the creator
    created_date = models.DateTimeField(auto_now_add=True)  # Automatic creation date
    question_type = models.CharField(max_length=15, choices=QUESTION_TYPE_CHOICES)
    explanation = models.TextField(blank=True)
    folder = models.ForeignKey(Folder, on_delete=models.CASCADE, related_name='fill_questions', blank=True, null=True)
    tags = models.ManyToManyField(Tag, related_name='fill_questions', blank=True)
    
    def __str__(self):
        return self.statement

class FillAnswers(models.Model):
    question = models.ForeignKey(FillQuestions, related_name='answers', on_delete=models.CASCADE)  # Reference to the fill in the blanks statement
    answer = models.TextField()  # To store the answer for the associated statement
    folder = models.ForeignKey(Folder, on_delete=models.CASCADE, related_name='fill_answers', blank=True, null=True)

    def __str__(self):
        return f"Answer to: {self.question}"

class CheckStatement(models.Model):
    statement = models.CharField(max_length=255)
    created_by = models.EmailField(max_length=100)
    created_date = models.DateTimeField(auto_now=True)
    QUESTION_TYPE_CHOICES = [
        ('MCQ', 'Multiple Choice Question'),
        ('FIB', 'Fill in the Blanks'),
        ('SUB', 'Subjective'),
        ('TRUEFALSE', 'True or False'),
        ('IMAGE', 'Diagram Study'),
    ]
    question_type = models.CharField(max_length=15, choices=QUESTION_TYPE_CHOICES)
    explanation = models.TextField(blank=True)
    folder = models.ForeignKey(Folder, on_delete=models.CASCADE, related_name='check_statements', blank=True, null=True)
    tags = models.ManyToManyField(Tag, related_name='check_statements', blank=True)
    
    

    def __str__(self):
        return self.statement[:50]

class TrueFalse(models.Model):
    statement = models.ForeignKey(CheckStatement,related_name='answers', on_delete=models.CASCADE)
    ans = models.CharField(max_length=100)  # Assuming a maximum length for the answer
    folder = models.ForeignKey(Folder, on_delete=models.CASCADE, related_name='true_false', blank=True, null=True)
    
    def __str__(self):
        return f"{self.statement.statement[:50]} - {self.ans}"
        

from djongo import models  # Import from djongo, not django.db.models
class Feedback(models.Model):
    #_id = models.ObjectIdField(auto_created=True, primary_key=True)  # Ensure _id is auto-generated
    #_id = djongo_models.ObjectIdField(primary_key=True, default=ObjectId)
    
    FEEDBACK_CHOICES = [
        ('easily recalled', 'Easily Recalled'),
        ('partially recalled', 'Partially Recalled'),
        ('forgot', 'Forgot'),
        ('skip', 'Skip'),
        ('recalled with effort', 'Recalled With Effort'),
    ]

    FLASHCARD_TYPE_CHOICES = [
        ('MCQ', 'Multiple Choice Question'),
        ('FIB', 'Fill in the Blanks'),
        ('SUB', 'Subjective'),
        ('TRUEFALSE', 'True or False'),
        ('IMAGE', 'Diagram Study'),
    ]

    flashcard_type = models.CharField(max_length=15, choices=FLASHCARD_TYPE_CHOICES, default='MCQ')
    flashcard_id = models.CharField(max_length=255)
    feedback = models.CharField(max_length=21, choices=FEEDBACK_CHOICES, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=255)  # To store user._id from JWT token

    class Meta:
        #unique_together = ['feedback']
        pass

    def clean(self):
        # Get the appropriate question model based on flashcard_type
        model_mapping = {
            'MCQ': MCQuestion,
            'FIB': FillQuestions,
            'SUB': Question,
            'TRUEFALSE': CheckStatement,
        }
        
        question_model = model_mapping.get(self.flashcard_type)
        if question_model:
            try:
                question = question_model.objects.get(id=self.flashcard_id)
                if str(question.created_by) != str(self.created_by):
                    raise ValidationError('You can only provide feedback for questions you created.')
            except question_model.DoesNotExist:
                raise ValidationError(f'No {self.flashcard_type} question found with ID: {self.flashcard_id}')

    def __str__(self):
        return f"{self.get_flashcard_type_display()} - {self.flashcard_id} - {self.feedback}"
    
    def get_related_data(self):

        models_mapping = {
            'MCQ': (MCQuestion, MCQAnswer),
            'FIB': (FillQuestions, FillAnswers),
            'SUB': (Question, Answer),
            'TRUEFALSE': (CheckStatement, TrueFalse)
        }

        related_data = None
        related_answer = None
        model_tuple = models_mapping.get(self.flashcard_type)

        if model_tuple:
            question_model, answer_model = model_tuple
            try:
                # Convert the flashcard_id to ObjectId
                related_data = question_model.objects.get(id=self.flashcard_id)
                related_answer = answer_model.objects.filter(question=related_data).first()
                related_data.update_next_review_date(self.feedback)
            except question_model.DoesNotExist:
                # Handle error if needed
                pass

        return related_data, related_answer
    
from djongo import models as djongo_models
    
class ReviewSettings(models.Model):
    _id = djongo_models.ObjectIdField(primary_key=True, default=ObjectId)
    created_by = models.CharField(max_length=100, unique=True)
    forgot_minutes = models.IntegerField(default=1)
    recalled_with_effort_hours = models.IntegerField(default=2)
    partially_recalled_hours = models.IntegerField(default=4)
    easily_recalled_days = models.IntegerField(default=1)
    skip_hours = models.IntegerField(default=1)

    class Meta:
        db_table = 'review_settings'

    def __str__(self):
        return f"ReviewSettings for {self.created_by}"

class ReviewSchedule(models.Model):
    _id = djongo_models.ObjectIdField(primary_key=True, default=ObjectId)
    flashcard_id = models.CharField(max_length=255)
    flashcard_type = models.CharField(max_length=15)
    next_review_date = models.DateTimeField(default=timezone.now)
    created_by = models.CharField(max_length=100)
    last_feedback = models.CharField(max_length=50, default='new')
    review_count = models.IntegerField(default=0)
    ease_factor = models.FloatField(default=2.5)
    interval = models.IntegerField(default=0)

    class Meta:
        db_table = 'review_schedule'
        indexes = [
            models.Index(fields=['next_review_date']),
            models.Index(fields=['created_by']),
            models.Index(fields=['flashcard_id', 'flashcard_type'])
        ]

    def save(self, *args, **kwargs):
        if not self._id:
            self._id = ObjectId()
        super().save(*args, **kwargs)

    def calculate_next_interval(self, feedback):
        try:
            settings = ReviewSettings.objects.get(created_by=self.created_by)
        except ReviewSettings.DoesNotExist:
            # SR is OFF → do not schedule
            raise ImproperlyConfigured("Spaced repetition is disabled for this user.")

        if feedback == "forgot":
            self.ease_factor = max(1.3, self.ease_factor - 0.2)
            self.interval = 0
            return timezone.now() + timedelta(minutes=settings.forgot_minutes)

        elif feedback == "recalled with effort":
            self.ease_factor = max(1.3, self.ease_factor - 0.15)
            self.interval = 1 if self.interval == 0 else round(self.interval * self.ease_factor)
            return timezone.now() + timedelta(hours=settings.recalled_with_effort_hours)

        elif feedback == "partially recalled":
            self.interval = 1 if self.interval == 0 else round(self.interval * self.ease_factor)
            return timezone.now() + timedelta(hours=settings.partially_recalled_hours)

        elif feedback == "easily recalled":
            self.ease_factor = min(2.5, self.ease_factor + 0.15)
            self.interval = 1 if self.interval == 0 else round(self.interval * self.ease_factor)
            return timezone.now() + timedelta(days=settings.easily_recalled_days)

        elif feedback == "skip":
            return timezone.now() + timedelta(hours=settings.skip_hours)

        return timezone.now() + timedelta(hours=1)

    def set_next_review_date(self, feedback):
        """
        Sets the next review date based on feedback and updates card statistics
        """
        try:
            print(f"Processing feedback: {feedback} for card {self.flashcard_id}")
            
            self.last_feedback = feedback
            self.next_review_date = self.calculate_next_interval(feedback)
            self.review_count += 1
            
            print(f"Next review scheduled for: {self.next_review_date}")
            print(f"Current ease factor: {self.ease_factor}")
            print(f"Current interval: {self.interval} days")
            
            self.save()
            
        except Exception as e:
            print(f"Error in set_next_review_date: {str(e)}")
            raise

    def __str__(self):
        return f"ReviewSchedule for {self.flashcard_type} ID {self.flashcard_id}"

    def get_review_status(self):
        """
        Returns the current review status of the flashcard
        """
        now = timezone.now()
        if self.next_review_date <= now:
            time_overdue = now - self.next_review_date
            return {
                'status': 'due',
                'hours_overdue': time_overdue.total_seconds() / 3600,
                'review_count': self.review_count,
                'last_feedback': self.last_feedback,
                'next_review': self.next_review_date,
                'ease_factor': self.ease_factor,
                'interval': self.interval
            }
        else:
            time_until_due = self.next_review_date - now
            return {
                'status': 'scheduled',
                'hours_until_due': time_until_due.total_seconds() / 3600,
                'review_count': self.review_count,
                'last_feedback': self.last_feedback,
                'next_review': self.next_review_date,
                'ease_factor': self.ease_factor,
                'interval': self.interval
            }

# models.py
from djongo import models as djongo_models
from bson import ObjectId

class PracticeLog(models.Model):
    _id = djongo_models.ObjectIdField(primary_key=True, default=ObjectId)  # safe with Djongo
    flashcard_type = models.CharField(max_length=15)   # reuse same values as Feedback
    flashcard_id = models.CharField(max_length=255)
    #action = models.CharField(max_length=50, default='practice_feedback')  # e.g. viewed, practised, etc.
    feedback = models.CharField(max_length=21, blank=True, null=True)      # optional: the user’s rating
    #duration_seconds = models.IntegerField(blank=True, null=True)          # optional
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=255)

    # Optional free-form context (works with Djongo)
    meta = djongo_models.JSONField(blank=True, null=True)

    class Meta:
        db_table = 'practice_log'
        indexes = [
            models.Index(fields=['created_by', 'created_at']),
            models.Index(fields=['flashcard_id', 'flashcard_type']),
        ]

    def __str__(self):
        return f"{self.created_by} {self.action} {self.flashcard_type}:{self.flashcard_id}"




class UploadedImage(models.Model):
    QUESTION_TYPE_CHOICES = [
        ('MCQ', 'Multiple Choice Question'),
        ('FIB', 'Fill in the Blanks'),
        ('SUB', 'Subjective'),
        ('TRUEFALSE', 'True or False'),
        ('IMAGE', 'Diagram Study'),
    ]

    folder = models.ForeignKey(
        Folder, on_delete=models.CASCADE, related_name='upload_images',
        blank=True, null=True
    )
    tags = models.ManyToManyField(Tag, related_name='upload_images', blank=True)
    created_by = models.CharField(max_length=100)
    created_date = models.DateTimeField(auto_now_add=True)
    question_type = models.CharField(max_length=15, choices=QUESTION_TYPE_CHOICES)
    statement = models.TextField(blank=True, null=True)
    masks = models.JSONField(blank=True, null=True)
    explanation = models.TextField(blank=True, null=True)
    gridfs_id = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return f"Image {self.id} - {self.statement}"
    

class UserSession(models.Model):
    id = models.CharField(max_length=255, primary_key=True)  # ✅ Change id to CharField
    user_id = models.CharField(max_length=255)
    login_time = models.DateTimeField(auto_now_add=True)
    logout_time = models.DateTimeField(null=True, blank=True)
    duration = models.DurationField(null=True, blank=True)
    session_status = models.CharField(max_length=20, default='active')

    def save(self, *args, **kwargs):
        if not self.id:  # ✅ Ensure id is always a string
            self.id = str(ObjectId())  # Generate MongoDB-style ObjectId
        super().save(*args, **kwargs)

    class Meta:
        db_table = 'user_sessions'

    def calculate_duration(self):
        if self.logout_time and self.login_time:
            self.duration = self.logout_time - self.login_time
            self.save(update_fields=['duration'])
        return self.duration

    def __str__(self):
        status = "Active" if self.session_status == 'active' else "Ended"
        duration = str(self.duration) if self.duration else "ongoing"
        return f"Session for {self.user_id} - {status} ({duration})"


    
from bson import ObjectId
from djongo import models
from .fields import CustomObjectIdField
    
class User(AbstractBaseUser, PermissionsMixin):
    _id = models.ObjectIdField(primary_key=True, editable=False)  # MongoDB's _id field
    # id = models.CharField(max_length=255, unique=True, editable=False)
    email = models.EmailField(max_length=255, verbose_name=_("Email Address"), unique=True, null=False, blank=False)
    first_name = models.CharField(max_length=100, verbose_name=_("First Name"))
    last_name = models.CharField(max_length=100, verbose_name=_("Last Name"))
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_verified=models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    date_joined = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(auto_now=True)
    

    USERNAME_FIELD = "email"

    REQUIRED_FIELDS = ["first_name", "last_name"]

    objects = UserManager()

   

    ROLE_CHOICES = (
    ('admin', 'Admin'),
    ('custom', 'Custom'),  # <-- Add this line
    )
    role = models.CharField(max_length=10)
    role_name = models.CharField(max_length=100, blank=True, null=True)  # For custom roles


    # Normalize email to lowercase
    def save(self, *args, **kwargs):
        # Normalize email to lowercase
        if self.email:
            self.email = self.email.strip().lower() 
        super().save(*args, **kwargs)

    def __str__(self):
        return self.email
    
    @property
    def get_full_name(self):
        return f"{self.first_name} {self.last_name}"
    
    def tokens(self, session_id=None):
        # Create the refresh token for the user
        refresh = RefreshToken.for_user(self)
        refresh['user_id'] = str(self._id)  # Add user ID to the refresh token

        # Fetch the most recent active session for the user
        session = UserSession.objects.filter(
            user_id=str(self._id),
            session_status='active',
            

        ).last()

        if session:
            # Ensure session_id is correctly retrieved
            session_id = session.id  # The session ID is the primary key of the UserSession model
            print(f"Session ID: {session_id}")  # Debug log to confirm the session ID

            # Attach session_id to both the refresh token and the access token
            refresh['session_id'] = str(session_id)  # Add session ID to refresh token

            # Create an access token from the refresh token
            access = refresh.access_token
            # ✅ Attach session_id to access token
            if session_id:
                access['session_id'] = str(session_id)  # Ensure it's a string  # Add session ID to access token

            print(f"Access Token with session_id: {access}")  # Debug log to check the token content

            # Return the tokens
            return {
                'refresh': str(refresh),
                'access': str(access),
            }
        else:
            raise ValueError("No active session found for user.")
        





class OneTimePassword(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, db_index=True)  # Add db_index=True
    code = models.CharField(max_length=6, unique=True, default="")
    created_at = models.DateTimeField(auto_now=True)  # Track OTP creation timet to preserve the original timestamp
    last_sent_at = models.DateTimeField(null=True, blank=True)  # Track the last OTP sent time

    def __str__(self):
        return f"{self.user.first_name} - passcode"


class InvalidToken(models.Model):
    user_id = models.CharField(max_length=255)
    token = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'invalid_tokens'



#Quiz
class Quiz(models.Model):
    
    #user = models.ForeignKey(User, on_delete=models.CASCADE)
    created_by = models.CharField(max_length= 50, default='Admin')
    folder = models.ForeignKey(Folder, on_delete=models.CASCADE)  # Or subfolder
    total_questions = models.IntegerField(default=0)
    attempted_questions = models.IntegerField(default=0)
    correct_answers = models.IntegerField(default=0)
    started_at = models.DateTimeField(auto_now_add=True)
    ended_at = models.DateTimeField(null=True, blank=True)
    passing_percentage = models.FloatField(default=35.0)
    max_attempts = models.IntegerField(null=True, blank=True)

    def __str__(self):
        return f"Quiz {self.id} by {self.created_by}"


from django.db import models
from django.utils import timezone

class QuizAttempt(models.Model):
    quiz = models.ForeignKey('Quiz', on_delete=models.CASCADE, related_name='attempts')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)  # Use AUTH_USER_MODEL
    attempted_questions = models.IntegerField()
    total_questions = models.IntegerField()
    correct_answers = models.IntegerField()
    wrong_answers = models.IntegerField()
    final_score = models.FloatField()
    score_percentage = models.FloatField()
    passing_percentage = models.FloatField()
    result = models.CharField(max_length=10)  # e.g., "Pass" or "Fail"
    quiz_status = models.CharField(max_length=20)  # e.g., "Completed" or "In Progress"
    started_at = models.DateTimeField(default=timezone.now)
    ended_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.user} - {self.quiz} - Attempt {self.attempt_number}"


#Time_Spent

class ReviewSession(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    flashcard_id = models.CharField(max_length=255)
    flashcard_type = models.CharField(max_length=50, choices=[('MCQ', 'MCQ'), ('FIB', 'FIB'), ('SUB', 'SUB'), ('TRUEFALSE', 'TRUEFALSE')])
    time_spent = models.FloatField(help_text="Time spent on the flashcard in hours")  # Time in hours
    reviewed_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"ReviewSession for {self.flashcard_id} by {self.user} at {self.reviewed_at}"

#Profile Management

from django.db import models
from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.conf import settings

class UserProfile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='profile')
    admission_number = models.CharField(max_length=50, unique=True)
    date_of_joining = models.DateField()
    dob = models.DateField()
    fathers_name = models.CharField(max_length=100)
    fathers_occupation = models.CharField(max_length=100, blank=True, null=True)
    fathers_phone = models.CharField(max_length=15, blank=True, null=True)
    mothers_name = models.CharField(max_length=100)
    mothers_occupation = models.CharField(max_length=100, blank=True, null=True)
    mothers_phone = models.CharField(max_length=15, blank=True, null=True)
    emergency_contact_number = models.CharField(max_length=15)
    guardian_name = models.CharField(max_length=100, blank=True, null=True)
    relationship_with_guardian = models.CharField(max_length=50, blank=True, null=True)
    guardian_phone = models.CharField(max_length=15, blank=True, null=True)
    permanent_address = models.TextField()
    current_address = models.TextField()
    blood_group = models.CharField(max_length=5)
    email = models.EmailField()
    alternate_email = models.EmailField(blank=True, null=True)
    gender = models.CharField(max_length=10, choices=[('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other')])
    photo = models.ImageField(upload_to='profile_photos/', blank=True, null=True)
    student_class = models.CharField(max_length=50)
    school = models.CharField(max_length=100)
    religion = models.CharField(max_length=50, blank=True, null=True)
    caste = models.CharField(max_length=50, blank=True, null=True)
    mother_tongue = models.CharField(max_length=50, blank=True, null=True)
    physically_challenged = models.BooleanField(default=False)
    height = models.FloatField(help_text="Height in cm")
    weight = models.FloatField(help_text="Weight in kg")

    def __str__(self):
        return f"{self.user.email}'s Profile - {self.admission_number}"

    def delete(self, *args, **kwargs):
        # Clear the admission number before deleting the profile
        self.admission_number = None
        self.save(update_fields=['admission_number'])
        super().delete(*args, **kwargs)





class UserPermission(models.Model):
    user = models.OneToOneField('User', on_delete=models.CASCADE, related_name='permissions', null=True, blank=True)
    role = models.CharField(max_length=15, choices=User.ROLE_CHOICES, null=True, blank=True)
    # Folder & Subfolder CRUD
    can_create_folder = models.BooleanField(default=True)
    can_read_folder = models.BooleanField(default=True)
    can_update_folder = models.BooleanField(default=True)
    can_delete_folder = models.BooleanField(default=True)

    # Question/Answer CRUD (all types: MCQ, FIB, SUB, TRUEFALSE)
    can_create_mcq = models.BooleanField(default=True)
    can_read_mcq = models.BooleanField(default=True)
    can_update_mcq = models.BooleanField(default=True)
    can_delete_mcq = models.BooleanField(default=True)
    can_create_sub = models.BooleanField(default=True)
    can_read_sub = models.BooleanField(default=True)
    can_update_sub = models.BooleanField(default=True)
    can_delete_sub = models.BooleanField(default=True)
    can_create_fib = models.BooleanField(default=True)
    can_read_fib = models.BooleanField(default=True)
    can_update_fib = models.BooleanField(default=True)
    can_delete_fib = models.BooleanField(default=True)
    can_create_tf = models.BooleanField(default=True)
    can_read_tf = models.BooleanField(default=True)
    can_update_tf = models.BooleanField(default=True)
    can_delete_tf = models.BooleanField(default=True)

    # Start Flashcard/Quiz
    can_start_flashcard = models.BooleanField(default=True)
    can_start_quiz = models.BooleanField(default=True)
    can_view_quiz_questions = models.BooleanField(default=True)
    can_submit_quiz_answers = models.BooleanField(default=True)
    can_view_quiz_result = models.BooleanField(default=True)
    can_view_quiz_attempt_result = models.BooleanField(default=True)
    can_view_quiz_history = models.BooleanField(default=True)
    # User profile CRUD
    can_create_profile = models.BooleanField(default=True)
    can_read_profile = models.BooleanField(default=True)
    can_update_profile = models.BooleanField(default=True)
    can_delete_profile = models.BooleanField(default=True)

    # Custom Role Management
    can_register_custom = models.BooleanField(default=False)
    can_create_custom_role = models.BooleanField(default=False) 
    can_view_all_custom_roles = models.BooleanField(default=False)
    can_set_custom_role_permission = models.BooleanField(default=False)
    can_view_custom_role_permission = models.BooleanField(default=False)
    can_change_user_role = models.BooleanField(default=False)
    can_view_users_of_custom_roles = models.BooleanField(default=False)
    can_delete_custom_role = models.BooleanField(default=False)
    can_delete_user = models.BooleanField(default=False)
    can_view_user_details = models.BooleanField(default=False)
    can_view_users_under_a_role = models.BooleanField(default=False)

    can_import_folder = models.BooleanField(default=False)
    can_export_folder = models.BooleanField(default=False)
    

    def __str__(self):
        if self.user:
            return f"Permissions for {self.user.email}"
        elif self.role:
            return f"Permissions for role {self.role}"
        return "Permissions"



from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()

class CustomRole(models.Model):
    name = models.CharField(max_length=100, unique=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    permissions = models.JSONField(default=dict)  # ✅ TRUE/FALSE support
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name



class CustomRolePermission(models.Model):
    role = models.ForeignKey(CustomRole, on_delete=models.CASCADE, related_name='custom_permissions')
    role_name = models.CharField(max_length=100, blank=True)  # <-- Add this line
    permissions = models.JSONField(default=dict)  # store as {"perm1": true, "perm2": false}
    
    # Folder & Subfolder CRUD
    can_create_folder = models.BooleanField(default=True)
    can_read_folder = models.BooleanField(default=True)
    can_update_folder = models.BooleanField(default=True)
    can_delete_folder = models.BooleanField(default=True)

    # Question/Answer CRUD (all types: MCQ, FIB, SUB, TRUEFALSE)
    can_create_mcq = models.BooleanField(default=True)
    can_read_mcq = models.BooleanField(default=True)
    can_update_mcq = models.BooleanField(default=True)
    can_delete_mcq = models.BooleanField(default=True)
    can_create_sub = models.BooleanField(default=True)
    can_read_sub = models.BooleanField(default=True)
    can_update_sub = models.BooleanField(default=True)
    can_delete_sub = models.BooleanField(default=True)
    can_create_fib = models.BooleanField(default=True)
    can_read_fib = models.BooleanField(default=True)
    can_update_fib = models.BooleanField(default=True)
    can_delete_fib = models.BooleanField(default=True)
    can_create_tf = models.BooleanField(default=True)
    can_read_tf = models.BooleanField(default=True)
    can_update_tf = models.BooleanField(default=True)
    can_delete_tf = models.BooleanField(default=True)

    # Start Flashcard/Quiz
    can_start_flashcard = models.BooleanField(default=True)
    can_start_quiz = models.BooleanField(default=True)
    can_view_quiz_questions = models.BooleanField(default=True)
    can_submit_quiz_answers = models.BooleanField(default=True)
    can_view_quiz_result = models.BooleanField(default=True)
    can_view_quiz_attempt_result = models.BooleanField(default=True)
    can_view_quiz_history = models.BooleanField(default=True)
    # User profile CRUD
    can_create_profile = models.BooleanField(default=True)
    can_read_profile = models.BooleanField(default=True)
    can_update_profile = models.BooleanField(default=True)
    can_delete_profile = models.BooleanField(default=True)
    
    
    can_register_custom = models.BooleanField(default=False)
    can_create_custom_role = models.BooleanField(default=False) 
    can_view_all_custom_roles = models.BooleanField(default=False)
    can_set_custom_role_permission = models.BooleanField(default=False)
    can_view_custom_role_permission = models.BooleanField(default=False)
    can_change_user_role = models.BooleanField(default=False)
    can_view_users_of_custom_roles = models.BooleanField(default=False)
    can_delete_custom_role = models.BooleanField(default=False)
    can_delete_user = models.BooleanField(default=False)
    can_view_user_details = models.BooleanField(default=False)
    can_view_users_under_a_role = models.BooleanField(default=False)

    can_import_folder = models.BooleanField(default=False)
    can_export_folder = models.BooleanField(default=False)

    def __str__(self):
        return f"Permissions for {self.role.name}"





