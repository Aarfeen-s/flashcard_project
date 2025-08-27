from rest_framework import serializers
from .models import MCQuestion, MCQAnswer, PracticeLog, Question, Answer, FillQuestions, FillAnswers, CheckStatement, Quiz, ReviewSchedule, ReviewSettings, TrueFalse, Folder, UploadedImage, File, Feedback,Tag, User, UserSession, InvalidToken
from random import shuffle
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.conf import settings
from django.urls import reverse
from .utils import send_normal_email
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.utils import timezone
from django.db.models import F
from .mixins import SessionTrackingMixin
from django.db import transaction
from rest_framework.response import Response
from rest_framework import status

class TagSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tag
        fields = ['id', 'name']

class MCQAnswerSerializer(serializers.ModelSerializer):
    # question_id = serializers.PrimaryKeyRelatedField(queryset=MCQuestion.objects.all(), source='question', write_only=True)
    class Meta:
        model = MCQAnswer
        fields = [ 'answer_text', 'is_correct']
   

    def to_representation(self, instance):
        data = super().to_representation(instance)
        return data

    def shuffle_answers(self, answers):
        shuffled_answers = answers[:]
        shuffle(shuffled_answers)
        return shuffled_answers

  # Import Tag Serializer



class MCQuestionSerializer(serializers.ModelSerializer):
    answers = MCQAnswerSerializer(many=True, required=False)
    # answers = serializers.CharField(max_length = 255, write_only=True)
    subfolder_id = serializers.PrimaryKeyRelatedField(source='folder_id', queryset=Folder.objects.all(), required=False, allow_null=True)
    tags = TagSerializer(many=True, required=False)

    class Meta:
        model = MCQuestion
        fields = ['id','statement', 'created_date', 'created_by', 'question_type', 'explanation', 'answers', 'subfolder_id', 'tags']
        read_only_fields = ['created_date', 'created_by']


        
        

    def create(self, validated_data):
        answers_data = validated_data.pop('answers', [])
        tags_data = validated_data.pop('tags', [])
        folder_id = validated_data.pop('folder_id', None)

        user_id = self.context['request'].user._id  # Assuming `user_id` is extracted from JWT token

    # Ensure created_by is added to validated_data
        validated_data['created_by'] = user_id 

        question = MCQuestion.objects.create(**validated_data)

        if folder_id:
            question.folder_id = folder_id
            question.save()

        for answer_data in answers_data:
            MCQAnswer.objects.create(question=question, **answer_data)
        
        # Handling tags
        if tags_data:
            tag_instances = []
            for tag_data in tags_data:
                tag_instance, created = Tag.objects.get_or_create(name=tag_data['name'])
                tag_instances.append(tag_instance)
            question.tags.set(tag_instances)

        return question

    def update(self, instance, validated_data):
        instance.statement = validated_data.get('statement', instance.statement)
        instance.created_date = validated_data.get('created_date', instance.created_date)
        instance.created_by = validated_data.get('created_by', instance.created_by)
        instance.question_type = validated_data.get('question_type', instance.question_type)
        instance.explanation = validated_data.get('explanation', instance.explanation)
        
        folder_id = validated_data.get('folder_id', None)
        if folder_id:
            instance.folder_id = folder_id

        # Update answers
        answers_data = validated_data.pop('answers', [])
        existing_answers = {answer.id: answer for answer in instance.answers.all()}

        for answer_data in answers_data:
            answer_id = answer_data.get('id', None)
            if answer_id and answer_id in existing_answers:
                answer_instance = existing_answers[answer_id]
                answer_instance.answer_text = answer_data.get('answer_text', answer_instance.answer_text)
                answer_instance.is_correct = answer_data.get('is_correct', answer_instance.is_correct)
                answer_instance.save()
            else:
                MCQAnswer.objects.create(question=instance, **answer_data)

        # Remove answers that are not in the update data
        for answer_id in existing_answers.keys():
            if answer_id not in [answer.get('id') for answer in answers_data]:
                existing_answers[answer_id].delete()

        # Update tags
        tags_data = validated_data.pop('tags', [])
        if tags_data:
            tag_instances = []
            for tag_data in tags_data:
                tag_instance, created = Tag.objects.get_or_create(name=tag_data['name'])
                tag_instances.append(tag_instance)
            instance.tags.set(tag_instances)

        instance.save()
        return instance

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data['tags'] = TagSerializer(instance.tags.all(), many=True).data
        if 'answers' in data:
            data['answers'] = MCQAnswerSerializer().shuffle_answers(data['answers'])
        return data


class AnswerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Answer
        fields = ('id', 'answer_text')

class QuestionSerializer(serializers.ModelSerializer):
    answers = serializers.CharField(max_length=255, write_only=True)
    explanation = serializers.CharField(max_length=255, allow_blank=True, required=False)
    subfolder_id = serializers.PrimaryKeyRelatedField(source='folder_id', queryset=Folder.objects.all(), required=False, allow_null=True)
    tags = TagSerializer(many=True, required=False)

    class Meta:
        model = Question
        fields = ('id', 'statement', 'created_date', 'created_by', 'question_type', 'answers', 'explanation', 'subfolder_id', 'tags')
        read_only_fields = [ 'created_date', 'created_by']
        

    def create(self, validated_data):
        answers_data = validated_data.pop('answers')
        explanation_data = validated_data.pop('explanation', None)
        folder_id = validated_data.pop('folder_id', None)
        tags_data = validated_data.pop('tags', [])

        user_id = self.context['request'].user._id  # Assuming `user_id` is extracted from JWT token

    # Ensure created_by is added to validated_data
        validated_data['created_by'] = user_id 

        question = Question.objects.create(**validated_data)

        if folder_id:
            question.folder_id = folder_id
            question.save()

        if explanation_data:
            question.explanation = explanation_data
        question.save()

        Answer.objects.create(question=question, answer_text=answers_data)

        if tags_data:
            tag_instances = [Tag.objects.get_or_create(name=tag['name'])[0] for tag in tags_data]
            question.tags.set(tag_instances)

        return question

    def update(self, instance, validated_data):
        answers_data = validated_data.pop('answers')
        explanation_data = validated_data.pop('explanation', None)
        folder_id = validated_data.pop('folder_id', None)
        tags_data = validated_data.pop('tags', [])

        instance.statement = validated_data.get('statement', instance.statement)
        instance.created_date = validated_data.get('created_date', instance.created_date)
        instance.created_by = validated_data.get('created_by', instance.created_by)
        instance.question_type = validated_data.get('question_type', instance.question_type)

        if folder_id:
            instance.folder_id = folder_id

        if explanation_data is not None:
            instance.explanation = explanation_data

        instance.save()

        if answers_data:
            related_answer = instance.related_answers.first()
            if related_answer:
                related_answer.answer_text = answers_data
                related_answer.save()
        else:
            Answer.objects.create(question=instance, answer_text=answers_data)

        if tags_data:
            tag_instances = [Tag.objects.get_or_create(name=tag['name'])[0] for tag in tags_data]
            instance.tags.set(tag_instances)

        return instance

    def to_representation(self, instance):
        data = super().to_representation(instance)
        if instance.related_answers.exists():
            data['answers'] = instance.related_answers.first().answer_text
        else:
            data['answers'] = None

        data['tags'] = TagSerializer(instance.tags.all(), many=True).data
        return data

class FillAnswersSerializer(serializers.ModelSerializer):
    class Meta:
        model = FillAnswers
        fields = ('id', 'answer')

class FillQuestionsSerializer(serializers.ModelSerializer):
    answers = serializers.CharField(max_length=255)
    explanation = serializers.CharField(max_length=255, allow_blank=True, required=False)
    subfolder_id = serializers.PrimaryKeyRelatedField(source='folder_id', queryset=Folder.objects.all(), required=False, allow_null=True)
    tags = TagSerializer(many=True, required=False)

    class Meta:
        model = FillQuestions
        fields = ('id', 'statement', 'created_date', 'created_by', 'question_type', 'answers', 'explanation', 'subfolder_id', 'tags')
        read_only_fields = [ 'created_date', 'created_by']
    def create(self, validated_data):
        tags_data = validated_data.pop('tags',[])
        answers_data = validated_data.pop('answers')
        explanation_data = validated_data.pop('explanation', None)

        user_id = self.context['request'].user._id  # Retrieve user_id from the request context
        validated_data['created_by'] = user_id 
        folder_id = validated_data.pop('folder_id', None)
         

        
    

        question = FillQuestions.objects.create(**validated_data)

        if folder_id:
            question.folder_id = folder_id
            question.save()

        if explanation_data:
            question.explanation = explanation_data
            question.save()

        FillAnswers.objects.create(question=question, answer=answers_data)

        for tag_data in tags_data:
            tag, created = Tag.objects.get_or_create(**tag_data)
            question.tags.add(tag)

        return question

    def update(self, instance, validated_data):
        tags_data = validated_data.pop('tags')
        answers_data = validated_data.pop('answers')
        explanation_data = validated_data.pop('explanation', None)
        folder_id = validated_data.pop('folder_id', None)

        instance.statement = validated_data.get('statement', instance.statement)
        instance.created_by = validated_data.get('created_by', instance.created_by)
        instance.question_type = validated_data.get('question_type', instance.question_type)

        if folder_id:
            instance.folder_id = folder_id

        if explanation_data:
            instance.explanation = explanation_data

        instance.save()

        if answers_data:
            if instance.answers.exists():
                answer = instance.answers.first()
                answer.answer = answers_data
                answer.save()
            else:
                FillAnswers.objects.create(question=instance, answer=answers_data)

        instance.tags.clear()
        for tag_data in tags_data:
            tag, created = Tag.objects.get_or_create(**tag_data)
            instance.tags.add(tag)

        return instance

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data['answers'] = instance.answers.first().answer if instance.answers.exists() else None
        return data


# class TrueFalseSerializer(serializers.ModelSerializer):
#     folder_id = serializers.PrimaryKeyRelatedField(queryset=Folder.objects.all(), required=False, allow_null=True)
#     #tags = serializers.CharField(required=False, allow_blank=True)  # Single string for tags

#     class Meta:
#         model = TrueFalse
#         fields = ['id', 'ans', 'folder_id']

class TrueFalseSerializer(serializers.ModelSerializer):
    subfolder_id = serializers.PrimaryKeyRelatedField(source='folder_id', queryset=Folder.objects.all(), required=False, allow_null=True)

    class Meta:
        model = TrueFalse
        fields = ['id', 'ans', 'subfolder_id']

class CheckStatementSerializer(serializers.ModelSerializer):
    answers = serializers.BooleanField(allow_null=True)
    explanation = serializers.CharField(max_length=255, allow_blank=True, allow_null=True)
    subfolder_id = serializers.PrimaryKeyRelatedField(source='folder_id', queryset=Folder.objects.all(), required=False, allow_null=True)
    tags = TagSerializer(many=True, required=False)

    class Meta:
        model = CheckStatement
        fields = ('id', 'statement', 'created_by', 'created_date', 'question_type', 'answers', 'explanation', 'subfolder_id', 'tags')
        read_only_fields = [ 'created_date', 'created_by']
    def create(self, validated_data):
        truefalse_data = validated_data.pop('answers', None)
        explanation = validated_data.pop('explanation', None)
        folder_id = validated_data.pop('folder_id', None)
        tags_data = validated_data.pop('tags',[])

        user_id = self.context['request'].user._id  # Assuming `user_id` is extracted from JWT token

    # Ensure created_by is added to validated_data
        validated_data['created_by'] = user_id 

        statement_instance = CheckStatement.objects.create(**validated_data)

        if folder_id:
            statement_instance.folder_id = folder_id         
            statement_instance.save()

        if truefalse_data is not None:
            TrueFalse.objects.create(statement=statement_instance, ans=truefalse_data)

        if explanation is not None:
            statement_instance.explanation = explanation
            statement_instance.save()

        for tag_data in tags_data:
            tag, created = Tag.objects.get_or_create(**tag_data)
            statement_instance.tags.add(tag)

        return statement_instance

    def update(self, instance, validated_data):
        instance.statement = validated_data.get('statement', instance.statement)
        instance.created_by = validated_data.get('created_by', instance.created_by)
        instance.question_type = validated_data.get('question_type', instance.question_type)

        explanation = validated_data.get('explanation')
        if explanation is not None:
            instance.explanation = explanation

        folder_id = validated_data.get('folder_id', None)
        if folder_id:
            instance.folder_id = folder_id

        instance.save()

        truefalse_data = validated_data.get('answers')
        if truefalse_data is not None:
            if instance.answers.exists():
                ans_instance = instance.answers.first()
                ans_instance.ans = truefalse_data
                ans_instance.save()
            else:
                TrueFalse.objects.create(statement=instance, ans=truefalse_data)

        tags_data = validated_data.pop('tags')
        instance.tags.clear()
        for tag_data in tags_data:
            tag, created = Tag.objects.get_or_create(**tag_data)
            instance.tags.add(tag)

        return instance

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data['answers'] = instance.answers.first().ans if instance.answers.exists() else None
        return data

class FileSerializer(serializers.ModelSerializer):
    type = serializers.SerializerMethodField()

    class Meta:
        model = File
        fields = ('id', 'name', 'type', 'created_by', 'folder')
        read_only_fields = ['created_by']

    def get_type(self, obj):
        return 'file'
    


# class FolderSerializer(serializers.ModelSerializer):
#     subfolders = serializers.SerializerMethodField()

#     class Meta:
#         model = Folder
#         fields = ['id', 'name', 'parent','created_by', 'type', 'subfolders']
#         read_only_fields = ['created_by']

#     def get_subfolders(self, obj):
#         subfolders = Folder.objects.filter(parent=obj)
#         return FolderSerializer(subfolders, many=True).data

# class CreateFolderSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Folder
#         fields = ['name', 'parent', 'type']

# class CreateSubfolderSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Folder
#         fields = ['name', 'parent', 'type']


class FolderSerializer(serializers.ModelSerializer):
    subfolders = serializers.SerializerMethodField()
    
    class Meta:
        model = Folder
        fields = ['id', 'name', 'parent', 'created_by', 'type', 'subfolders']
        read_only_fields = ['created_by']

    def get_subfolders(self, obj):
        # Get current depth from context, default to 0
        depth = self.context.get('depth', 0)
        if depth >= 2:  # Limit to 2 levels (adjust as needed)
            return []
        subfolders = Folder.objects.filter(parent=obj)
        serializer = FolderSerializer(subfolders, many=True, context={'depth': depth + 1})
        return serializer.data

    def validate(self, data):
        parent = data.get('parent')
        # For create, self.instance is None
        if self.instance:
            # Prevent a folder from being its own parent
            if parent and self.instance.id == parent.id:
                raise serializers.ValidationError("A folder cannot be its own parent.")
            # Prevent cycles in the parent chain
            ancestor = parent
            while ancestor:
                if ancestor.id == self.instance.id:
                    raise serializers.ValidationError("Cannot create a cyclic folder structure.")
                ancestor = ancestor.parent
        else:
            # For create, check if parent is itself (should not happen, but extra safety)
            if parent and hasattr(parent, 'id') and parent.id is not None and parent.id == data.get('id', None):
                raise serializers.ValidationError("A folder cannot be its own parent.")
        return data


class CreateFolderSerializer(serializers.ModelSerializer):
    def validate(self, data):
        parent = data.get('parent')
        # Prevent a folder from being its own parent
        if parent and hasattr(parent, 'id') and parent.id == data.get('id', None):
            raise serializers.ValidationError("A folder cannot be its own parent.")
        return data

    class Meta:
        model = Folder
        fields = ['name', 'parent', 'type']

class CreateSubfolderSerializer(serializers.ModelSerializer):
    def validate(self, data):
        parent = data.get('parent')
        # Prevent a folder from being its own parent
        if parent and hasattr(parent, 'id') and parent.id == data.get('id', None):
            raise serializers.ValidationError("A folder cannot be its own parent.")
        return data

    class Meta:
        model = Folder
        fields = ['name', 'parent', 'type']




class MCQAnswerOnlySerializer(serializers.ModelSerializer):
    class Meta:
        model = MCQAnswer
        fields = ['id', 'answer_text', 'is_correct']

class MCQuestionOnlySerializer(serializers.ModelSerializer):
    # If you want to serialize folder and tags fields, you should define them properly.
    folder = serializers.PrimaryKeyRelatedField(queryset=Folder.objects.all(), required=False)  # Serialize folder as primary key
    tags = serializers.PrimaryKeyRelatedField(queryset=Tag.objects.all(), many=True, required=False)  # Serialize tags as primary keys

    class Meta:
        model = MCQuestion
        fields = ['id', 'statement', 'created_date', 'created_by', 'question_type', 'folder', 'tags']



class AnswersOnlySerializer(serializers.ModelSerializer):
    class Meta:
        model = Answer
        fields = ['id', 'answer_text']

class QuestionsOnlySerializer(serializers.ModelSerializer):
    related_answers = AnswersOnlySerializer(many=True, read_only=True)
    folder_id = serializers.PrimaryKeyRelatedField(queryset=Folder.objects.all(), required=False, allow_null=True)
    #tags = serializers.CharField(required=False, allow_blank=True)  # Single string for tags

    class Meta:
        model = Question
        fields = ['id', 'statement', 'created_by', 'question_type', 'related_answers', 'folder_id']

class FillQuestionOnlySerializer(serializers.ModelSerializer):
    folder_id = serializers.PrimaryKeyRelatedField(queryset=Folder.objects.all(), required=False, allow_null=True)
    #tags = serializers.CharField(required=False, allow_blank=True)  # Single string for tags

    class Meta:
        model = FillQuestions
        fields = ['id', 'statement', 'created_date', 'created_by', 'question_type', 'folder_id']

class FillAnswerOnlySerializer(serializers.ModelSerializer):
    class Meta:
        model = FillAnswers
        fields = ['id', 'answer']

class TrueFalseOnlySerializer(serializers.ModelSerializer):
    folder_id = serializers.PrimaryKeyRelatedField(queryset=Folder.objects.all(), required=False, allow_null=True)
    #tags = serializers.CharField(required=False, allow_blank=True)  # Single string for tags

    class Meta:
        model = TrueFalse
        fields = ['id', 'ans', 'folder_id']

class CheckStatementOnlySerializer(serializers.ModelSerializer):
    folder_id = serializers.PrimaryKeyRelatedField(queryset=Folder.objects.all(), required=False, allow_null=True)
    #subfolder_id = serializers.PrimaryKeyRelatedField(queryset=Folder.objects.all(), required=False, allow_null=True)
    #tags = serializers.CharField(required=False, allow_blank=True)  # Single string for tags

    class Meta:
        model = CheckStatement
        fields = ['id', 'statement', 'created_by', 'question_type', 'folder_id', ]

      
from rest_framework import serializers
from .models import MCQuestion, FillQuestions, TrueFalse, CheckStatement

class CombinedQuestionSerializer(serializers.ModelSerializer):
    question_type = serializers.SerializerMethodField()

    class Meta:
        model = None  # Placeholder for model
        fields = ('id', 'statement', 'created_date', 'created_by', 'question_type', 'explanation', 'answers', 'folder_id',)

    def get_question_type(self, instance):
        if isinstance(instance, MCQuestion):
            return 'MCQ'
        elif isinstance(instance, FillQuestions):
            return 'Fill-in-the-Blanks'
        elif isinstance(instance, CheckStatement):
            return 'True/False'
        elif isinstance(instance, Question):
            return 'SUB'
        else:
            return 'Unknown'

    def to_representation(self, instance):
        if isinstance(instance, MCQuestion):
            serializer = MCQuestionSerializer(instance)
        elif isinstance(instance, FillQuestions):
            serializer = FillQuestionsSerializer(instance)
        elif isinstance(instance, CheckStatement):
            serializer = CheckStatementSerializer(instance)
        elif isinstance(instance, Question):
            serializer = QuestionSerializer(instance)
        else:
            return None  # Handle error or unknown instance type
        
        return serializer.data

# serializers.py
class FeedbackSerializer(serializers.ModelSerializer):
    class Meta:
        model = Feedback
        fields = '__all__'

    def to_representation(self, instance):
        data = super().to_representation(instance)

        # 👇 Add this block first
        if self.context.get('suppress_schedule'):
            data['review_schedule'] = None
            return data
        # 👆 This will bypass SR logic if practice mode

        from .models import ReviewSettings, ReviewSchedule
        if ReviewSettings.objects.filter(created_by=instance.created_by).exists():
            try:
                sched = ReviewSchedule.objects.get(
                    flashcard_id=instance.flashcard_id,
                    flashcard_type=instance.flashcard_type,
                    created_by=instance.created_by
                )
                data['review_schedule'] = {
                    "next_review": sched.next_review_date,
                    "review_status": sched.get_review_status()
                }
            except ReviewSchedule.DoesNotExist:
                data['review_schedule'] = None
        else:
            data['review_schedule'] = None

        return data
class ObjectIdField(serializers.Field):
    def to_representation(self, value):
        if value is None:
            return None
        return str(value)

    def to_internal_value(self, data):
        if data is None or data == "":
            return None
        try:
            return ObjectId(data)
        except:
            raise serializers.ValidationError("Invalid ObjectId format.")

class ReviewSettingsSerializer(serializers.ModelSerializer):
    id = ObjectIdField(source="_id", read_only=True)   # 👈 bind to `_id`
    created_by = serializers.CharField(read_only=True)

    class Meta:
        model = ReviewSettings
        fields = ['id', 'created_by', 'forgot_minutes', 'recalled_with_effort_hours', 'partially_recalled_hours', 'easily_recalled_days', 'skip_hours']


class ReviewScheduleSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReviewSchedule
        fields = '__all__'

# serializers.py
class PracticeLogSerializer(serializers.ModelSerializer):
    created_by = serializers.CharField(read_only=True)

    class Meta:
        model = PracticeLog
        fields = '__all__'


from rest_framework import serializers
from .models import UploadedImage

class UploadedImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = UploadedImage
        fields = ['_id', 'statement', 'created_date', 'created_by', 'question_type', 'explanation', 'answers', 'subfolder_id', 'tags']
        read_only_fields = ['created_date', 'created_by']




class LoginSerializer(serializers.ModelSerializer, SessionTrackingMixin):
    email = serializers.EmailField(max_length=155, min_length=6)
    password = serializers.CharField(max_length=68, write_only=True)
    full_name = serializers.CharField(max_length=255, read_only=True)
    access_token = serializers.CharField(max_length=255, read_only=True)
    refresh_token = serializers.CharField(max_length=255, read_only=True)
    session_id = serializers.CharField(max_length=255, read_only=True)
    user_role = serializers.CharField(max_length=10, read_only=True)  # <-- Add this line

    class Meta:
        model = User
        fields = ['email', 'password', 'full_name', 'user_role', 'access_token', 'refresh_token', 'session_id']

    def validate(self, attrs):
        email = attrs.get('email').lower()  # Normalize email to lowercase
        password = attrs.get('password')
        request = self.context.get('request')
        user = authenticate(request, email=email, password=password)

        if not user:
            raise AuthenticationFailed("Invalid credentials, try again.")
        if not user.is_verified:
            raise AuthenticationFailed("Email is not verified.")

        current_time = timezone.now()
        user_id = str(user._id)

        # Create a new session without affecting existing ones
        new_session = UserSession.objects.create(
            user_id=user_id,
            login_time=current_time,
            session_status='active'
        )
        new_session
        print(f"Created session with ID: {new_session.id}")

        user_tokens = user.tokens()
        return {
            'email': user.email,
            'full_name': user.get_full_name,
            'user_role': user.role,  # <-- Add this line
            'access_token': str(user_tokens.get('access')),
            'refresh_token': str(user_tokens.get('refresh')),
            'session_id': str(new_session.id)  # Include the session ID in the response
        }



    
class LogoutUserSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()

    def validate(self, attrs):
        self.refresh_token = RefreshToken(attrs['refresh_token'])
        request = self.context.get('request')
        if request and request.user:
            self.user_id = str(request.user._id)
            print(f"Logout - Validated user_id: {self.user_id}")
        else:
            raise serializers.ValidationError("User not found in request")
        return attrs

    def save(self, **kwargs):
        try:
            with transaction.atomic():
                current_time = timezone.now()
                print(f"Logout - Processing for user: {self.user_id}")
                
                # Find active sessions
                active_sessions = UserSession.objects.filter(
                    user_id=self.user_id,
                    session_status='active',
                    logout_time__isnull=True
                )
                print(f"Found {active_sessions.count()} active sessions")

                # End active sessions
                for session in active_sessions:
                    session.logout_time = current_time
                    session.session_status = 'ended'
                    if session.login_time:
                        session.duration = current_time - session.login_time
                    session.save()
                    print(f"Ended session with login time: {session.login_time}")

                # Invalidate refresh token
                InvalidToken.objects.create(
                    user_id=self.user_id,
                    token=str(self.refresh_token)
                )
                print("Created InvalidToken entry")
            
            return True

        except Exception as e:
            print(f"Error in logout: {str(e)}")
            raise serializers.ValidationError(str(e))

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    def validate(self, attrs):
        email = attrs.get('email').lower()  # Normalize email to lowercase
        try:
            user = User.objects.get(email=email)
            
            uidb64 = urlsafe_base64_encode(smart_bytes(user._id))
            token = PasswordResetTokenGenerator().make_token(user)
            reset_link = f"{settings.FRONTEND_URL}/password-reset-confirm/{uidb64}/{token}/"

            # Customize the email format here
            email_subject = "Reset Your Password"
            email_body = f"""
            Hi {user.first_name},

            We received a request to reset your password. Click the link below to reset it:

            {reset_link}

            If you did not request a password reset, please ignore this email.

            Thanks,
            The Flashcard Team
            """
            send_normal_email({
                'email_subject': email_subject,
                'email_body': email_body,
                'to_email': email
            })
            
        except User.DoesNotExist:
            raise serializers.ValidationError("User with this email does not exist.")
        return attrs

class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=100, min_length=6, write_only=True)
    confirm_password = serializers.CharField(max_length=100, min_length=6, write_only=True)

    def validate(self, attrs):
        password = attrs.get('password')
        confirm_password = attrs.get('confirm_password')

        if password != confirm_password:
            raise serializers.ValidationError("Passwords do not match")
        return attrs
from django.utils import timezone
    


class LogoutUserSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()

    def validate(self, attrs):
        self.token = attrs['refresh_token']
        try:
            self.refresh_token = RefreshToken(self.token)
            self.user_id = str(self.refresh_token.payload.get('user_id'))
        
            if not self.user_id:
                raise serializers.ValidationError('Invalid token: no user_id found')

            self.user = self.context.get('request').user  # Ensure this user is correct
        
            print(f"Authenticated user ID (from request): {self.user._id}")
            print(f"Token user ID (from token): {self.user_id}")

            if str(self.user._id) != self.user_id:  # Ensure both are strings before comparing
                raise serializers.ValidationError('Token does not match the authenticated user.')

        except TokenError:
            raise serializers.ValidationError('Token is invalid or expired')
        except Exception as e:
            raise serializers.ValidationError(f"An error occurred: {str(e)}")

        return attrs

    def save(self, **kwargs):
        try:
            with transaction.atomic():
                current_time = timezone.now()
                print(f"Logout - Processing for user: {self.user_id}")

                # Get the current active session with lock to prevent race conditions
                active_session = UserSession.objects.select_for_update().filter(
                    user_id=self.user._id,
                    session_status='active'
                ).first()

                if active_session:
                    # End the session
                    active_session.logout_time = current_time
                    active_session.session_status = 'ended'
                    if active_session.login_time:
                        active_session.duration = current_time - active_session.login_time
                    active_session.save()

                    print(f"Ended session for user {self.user_id} with session ID {active_session.id}")

                # Invalidate the refresh token and access token by saving them in InvalidToken table
                InvalidToken.objects.create(
                    user_id=self.user._id,
                    token=str(self.refresh_token)
                )
                InvalidToken.objects.create(
                    user_id=self.user._id,
                    token=str(self.refresh_token.access_token)
                )

                print(f"Tokens invalidated for user {self.user_id}")

            return True
        except Exception as e:
            print(f"Error in logout: {str(e)}")
            return False

class VerifyUserEmailSerializer(serializers.Serializer):
    # email = serializers.EmailField(),
    otp = serializers.EmailField()


#Quiz
class QuizSerializer(serializers.ModelSerializer):
    class Meta:
        model = Quiz
        fields = ['id', 'created_by', 'folder', 'total_questions', 'attempted_questions', 'correct_answers', 'started_at', 'ended_at', 'passing_percentage']


from rest_framework import serializers
from .models import QuizAttempt

class QuizAttemptSerializer(serializers.ModelSerializer):
    class Meta:
        model = QuizAttempt
        fields = '__all__'

#Profile Management

from rest_framework import serializers
from .models import UserProfile

class UserProfileSerializer(serializers.ModelSerializer):

    user = serializers.CharField(source='user._id', read_only=True)  # Convert ObjectId to string
    
    class Meta:
        model = UserProfile
        fields = '__all__'
        read_only_fields = ['user']

#RBAC



from rest_framework import serializers
from .models import User, UserPermission

class UserRegisterSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'password', 'password2', 'role']

    # 👇 Add this method
    def validate_email(self, value):
        email = value.lower().strip()
        if User.objects.filter(email__iexact=email).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return email

    def validate(self, data):
        # Initial admin setup
        if self.context.get('initial_admin'):
            if data.get('role') != 'admin':
                raise serializers.ValidationError("Initial user must be admin.")
            if data['password'] != data['password2']:
                raise serializers.ValidationError("Passwords do not match.")
            return data

        # 🚫 Block admin registration except for initial admin
        if data.get('role') == 'admin':
            raise serializers.ValidationError("You are not allowed to register admin users.")

        request = self.context.get('request')
        allowed_roles = ['admin']
        if not request or not request.user.is_authenticated:
            raise serializers.ValidationError("Only admin or custom role users can register new users.")

        from .utils import has_permission

        role_to_register = data.get('role')

        # Check permissions for default users
        if request.user.role == 'admin':        
            # For custom roles
            if role_to_register not in allowed_roles and not has_permission(request.user, 'can_register_custom'):
                raise serializers.ValidationError(f"You do not have permission to register custom role: {role_to_register}.")

        if data['password'] != data['password2']:
            raise serializers.ValidationError("Passwords do not match.")
        return data



    def create(self, validated_data):
        validated_data.pop('password2')
        password = validated_data.pop('password')
        user = User(**validated_data)
        user.set_password(password)
        user.save()
        return user



from bson import ObjectId
from rest_framework import serializers
from .models import UserPermission

class ObjectIdField(serializers.Field):
    def to_representation(self, value):
        if value is None:
            return None
        return str(value)

    def to_internal_value(self, data):
        if data is None or data == "":
            return None
        try:
            return ObjectId(data)
        except:
            raise serializers.ValidationError("Invalid ObjectId format.")

class UserPermissionSerializer(serializers.ModelSerializer):
    id = ObjectIdField(read_only=True)  # ✅ Add this line
    user = ObjectIdField(required=False, allow_null=True)

    class Meta:
        model = UserPermission
        fields = '__all__'


from .models import CustomRole, CustomRolePermission

from rest_framework import serializers
from .models import CustomRole

class CustomRoleSerializer(serializers.ModelSerializer):
    id = serializers.SerializerMethodField()

    def get_id(self, obj):
        return str(obj.id) if obj.id else None

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data['created_by'] = str(instance.created_by) if instance.created_by else None
        return data

    class Meta:
        model = CustomRole
        fields = ['id', 'name', 'permissions', 'created_by']
        read_only_fields = ['created_by']



class CustomRolePermissionSerializer(serializers.ModelSerializer):
    role = serializers.PrimaryKeyRelatedField(queryset=CustomRole.objects.all())
    role_name = serializers.CharField(source='role.name', read_only=True)

    class Meta:
        model = CustomRolePermission
        fields = '__all__'



