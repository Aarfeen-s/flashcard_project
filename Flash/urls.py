from django.urls import path, include
from rest_framework.routers import DefaultRouter
from Flash import views
from rest_framework.routers import DefaultRouter
from django.conf import settings
from django.conf.urls.static import static
from django.urls import path, include
from .views import (AllReviewFlashcardsView, DueReviewFlashcardsView,MCQuestionViewSet,  MCQAnswerViewSet, PracticeLogViewSet, QuestionsViewSet,AnswersViewSet, 
FillQuestionViewSet, FillAnswerViewSet,CheckStatementViewSet, QuizViewSet, ReviewFlashcardsBySubfolderView, ReviewFlashcardsView, ReviewSettingsViewSet,TrueFalseViewSet,FeedbackViewSet, assign_custom_role_to_user, backup_mongodb, create_custom_role, custom_user_register_user, delete_folder_and_questions, export_all_questions_csv, get_current_user_permissions, get_custom_role_permissions, get_my_details, import_all_questions_csv, list_custom_roles, list_users_by_custom_role, mcq_crud,fib_crud, restore_mongodb, set_custom_role_permissions, sub_crud,truefalse_crud,manage_tags, 
QuestionFeedbackView, VerifyUserEmail,  TestingAuthenticatedReq,VerifyUserEmail, TestingAuthenticatedReq, PasswordResetConfirm, PasswordResetRequestView,manage_uploaded_images, validate_uploaded_image_answer, get_all_uploaded_images,
SetNewPasswordView, LogoutApiView, view_user_details, view_users_under_custom_role, weekly_summary, daily_summary, monthly_summary, get_user_sessions, ResendOTPView, admin_register_user, initial_admin_register, login_user, LoginUserView, delete_user)
from .views import GoogleLoginAPIView
from .views import get_quiz_attempt_result
from .views import UserProfileViewSet

router = DefaultRouter()
router.register(r'mcq-quesans', views.MCQuestionViewSet, basename='MCQ Flashcard')
router.register(r'mcqanswers', views.MCQAnswerViewSet)
router.register(r'sub-quesans', views.QuestionsViewSet, basename='SUB Flashcard')
router.register(r'sub-answer', views.AnswersViewSet, basename=' Sub Answer')
router.register(r'fillups-quesans', views.FillQuestionViewSet, basename='FILL UPS Flashcard')
router.register(r'fillanswers', views.FillAnswerViewSet)
router.register(r'truefalse-quesans', views.CheckStatementViewSet, basename= 'Check Statement')
router.register(r'folders', views.FolderViewSet, basename='Folder')
router.register(r'files', views.FileViewSet, basename= 'Files')
router.register(r'truefalse-answers', views.TrueFalseViewSet, basename= 'True False')
router.register(r'directory', views.DirectoryViewSet, basename='directory')
router.register(r'feedbacks', FeedbackViewSet, basename='feedback')
#router.register(r'quizzes', views.QuizViewSet)
router.register(r'quiz', QuizViewSet, basename='quiz')
router.register(r'profile', UserProfileViewSet, basename='userprofile')
router.register(r'review-settings', ReviewSettingsViewSet, basename='review-settings')
router.register(r'practice-logs', PracticeLogViewSet, basename='practice-logs')

urlpatterns = [
    path('', include(router.urls)),
    path('subfolder/<int:pk>/create_subfolder/', views.FolderViewSet.as_view({'post': 'create_subfolder_by_subfolder_id'})),    #Done
    path('folders/<int:pk>/create_subfolder/', views.FolderViewSet.as_view({'post': 'create_subfolder_by_subfolder_id'}), name='create-subfolder'),  #Done
    path('mcq_questions/', views.mcq_questions, name='mcq_questions'),  #Done
    path('subfolder/<int:subfolder_id>/', views.get_questions_by_subfolder, name='get-questions-by-subfolder'),  #Done
    path('mcq_answers/', views.mcq_answers, name='mcq_answers'), #done
    path('FillupQuestions/', views.FillupQuestions, name='FillupQuestions'),  #done
    path('FillupAnswers/', views.FillupAnswers, name='FillupAnswers'), #done
    path('home/', views.home, name='home'),  #Done
    path('all_mcq_questions_and_answers/', views.all_mcq_questions_and_answers, name='all_mcq_questions_and_answers'),  #done
    path('all_fill_questions_and_answers/', views.all_fill_questions_and_answers, name='all_fill_questions_and_answers'), #done
    path('cards/', views.cards, name='cards'),  #Done
    path('flashcard/', views.flashcard, name='flashcard'),  # Done
    path('questions/combined/<int:folder_id>/', views.CombinedQuestionsByFolderAPIView.as_view(), name='combined-questions-by-folder'),
    path('feedback_detail/<int:feedback_id>/', views.feedback_detail, name='feedback_detail'),
    
    path('subfolder/<int:subfolder_id>/mcq/', mcq_crud),  #Done
    path('subfolder/<int:subfolder_id>/mcq/<str:question_id>/', mcq_crud,name='MCQ by subfolder'),  #Done
    path('subfolder/<int:subfolder_id>/fib/', fib_crud),  #Done
    path('subfolder/<int:subfolder_id>/fib/<int:question_id>/', fib_crud,name='Fill Ups by subfolder'),  #Done
    path('subfolder/<int:subfolder_id>/sub/', sub_crud),  #Done
    path('subfolder/<int:subfolder_id>/sub/<int:question_id>/', sub_crud,name='Subjective by subfolder'),  #Done
    path('subfolder/<int:subfolder_id>/truefalse/', truefalse_crud),  #Done
    path('subfolder/<int:subfolder_id>/truefalse/<int:question_id>/', truefalse_crud,name='Truefalse by subfolder'),  #Done

    path('subfolder/<int:subfolder_id>/tags/<str:question_type>/<int:question_id>/', manage_tags, name='manage_tags'), #done
    path('subfolder/<int:subfolder_id>/tags/<str:question_type>/<int:question_id>/<int:tag_id>/', manage_tags, name='manage_tags_with_tag_id'), #Done
    
    path('subfolder/<int:subfolder_id>/tags/<str:question_type>/<str:question_id>/', manage_tags, name='manage_tags'), #done mcq
    path('subfolder/<int:subfolder_id>/tags/<str:question_type>/<slug:question_id>/<int:tag_id>/', manage_tags, name='manage_tags_with_tag_id'), #Done mcq
    path('folder/<int:folder_id>/tags/<int:tag_id>/questions-answers/', views.get_questions_answers_by_tag, name='get_questions_answers_by_tag'),
    


    path('subfolder/<int:subfolder_id>/feedbacks/<str:question_type>/', QuestionFeedbackView.as_view(), name='question_feedback_list'),
    path('subfolder/<int:subfolder_id>/feedbacks/<str:question_type>/<str:question_id>/', QuestionFeedbackView.as_view(), name='question_feedback_detail'),
    path('subfolder/<int:subfolder_id>/feedbacks/<str:question_type>/<int:question_id>/', QuestionFeedbackView.as_view(), name='feedback_detail_update_delete'),
    



    path('subfolder/<int:subfolder_id>/uploaded_images/', views.manage_uploaded_images, name='manage_uploaded_images'),  #done
    path('subfolder/<int:subfolder_id>/uploaded_images/<int:question_id>/', views.manage_uploaded_images, name='manage_uploaded_image_detail'),  #done
    path('subfolder/<int:subfolder_id>/uploaded_images/<int:question_id>/validate/', validate_uploaded_image_answer, name='validate_uploaded_image_answer'),
    path('uploaded_images/', get_all_uploaded_images, name='all-uploaded-images'),
    path('gridfs_image/<str:file_id>/', views.get_gridfs_image, name='get_gridfs_image'),
    path('subfolders/<int:pk>/move_subfolder/', views.FolderViewSet.as_view({'post': 'move_subfolder'}), name='move-subfolder'),  #done
    path('review-schedule/', ReviewFlashcardsView.as_view(), name='review-schedule'),
    path('review-schedule/subfolder/<int:subfolder_id>/', ReviewFlashcardsBySubfolderView.as_view(), name='review-flashcards-by-subfolder'),
    path('flashcard-review/', AllReviewFlashcardsView.as_view(), name='flashcard-review/'),
    # path('register/', RegisterUserView.as_view(), name='register'),
    path('verify/', VerifyUserEmail.as_view(), name='verify'),
    path('login/', LoginUserView.as_view(), name='login'),
    
    path('test/', TestingAuthenticatedReq.as_view(), name='test'),
    path('password-reset/', PasswordResetRequestView.as_view(), name='password-reset'),
    path('password-reset-confirm/<str:uidb64>/<str:token>/', PasswordResetConfirm.as_view(), name='reset-password-confirm'),
    path('set-new-password/<uidb64>/<token>/', SetNewPasswordView.as_view(), name='set-new-password'),
    path('logout/', views.logout_user, name='logout'),
    path('weekly-summary/', weekly_summary, name='weekly-summary'),
    path('daily-summary/', daily_summary, name='daily_summary'),
    path('monthly-summary/', monthly_summary, name='monthly_summary'),
    path('yearly-summary/', views.yearly_summary, name='yearly-summary'),
    path('api/sessions/', get_user_sessions, name='user-sessions'),
    path('auth/sessions/', views.get_user_sessions, name='get_user_sessions'),
    path('auth/sessions/clear/', views.clear_sessions, name='clear_sessions'),
    path('auth/sessions/cleanup/', views.cleanup_user_sessions, name='cleanup_sessions'),
    path('clear-sessions/', views.clear_sessions, name='clear-sessions'),

    path('quiz/<int:quiz_id>/questions/', views.get_quiz_questions, name='get-quiz-questions'),
    path('quiz/<int:quiz_id>/submit/', views.submit_quiz_answers, name='submit-quiz-answers'),
    path('quiz/<int:quiz_id>/result/', views.get_quiz_result, name='quiz-result'),
    path('quiz/<int:quiz_id>/attempt/<int:attempt_number>/', get_quiz_attempt_result, name='get_quiz_attempt_result'),
    path('quiz-history/', views.quiz_history, name='quiz-history'),

    path('api/day-summary/', views.day_summary, name='day_summary'),
    path('api/week-summary/', views.week_summary, name='week_summary'),
    path('api/month-summary/', views.month_summary, name='month_summary'),
    path('api/year-summary/', views.year_summary, name='year_summary'),
    path('resend-otp/', ResendOTPView.as_view(), name='resend-otp'),

    path('auth/google/', GoogleLoginAPIView.as_view(), name='google_login'),

    path('api/backup/', views.backup_mongodb),
    path('api/restore/', views.restore_mongodb),
    path('api/merge/', views.merge_mongodb),

    #path('user/<str:user_id>/permissions/', user_permission_detail, name='user_permission_detail'),
    path('admins/register-user/', admin_register_user, name='admin_register_user'), #working POST
    path('register-initial-admin/', initial_admin_register, name='register_initial_admin'), #working POST any user AST

    #path('permissions/update/', update_permissions, name='update_permissions'), #working PUT, "role": "teacher" or "user_id": "60f1c2d3e4b5a6f7g8h9i0j1" checking
    
    #path('permissions/user/<str:user_id>/', get_user_permissions, name='get_user_permissions'), #checking GET
    #path('permissions/role/', get_user_permissions, name='get_role_permissions'),  # Use ?role=teacher etc. #working GET
    #path('permissions/me/', my_permissions, name='my_permissions'), #Working GET role, checking user id

    #path('users/', list_users_by_role, name='list_users_by_role'), #Working GET /users/?role=teacher 
    path('users/<str:user_id>/delete/', delete_user, name='delete_user'), #Working DELETE

    path('me/id-role/', views.get_my_user_id_and_role, name='get_my_user_id_and_role'),
    #path("change-user-role/", change_user_role, name="change-user-role"),
    path('export-questions-csv/', export_all_questions_csv, name='export-questions-csv'),
    path('import-questions-csv/', import_all_questions_csv, name='import-questions-csv'),

    path('delete-folder/<int:folder_id>/', delete_folder_and_questions),

    # Custom Roles
    path('custom-roles/create/', create_custom_role, name='create_custom_role'),
    path('custom-roles/', list_custom_roles, name='list_custom_roles'),
    path('custom-roles/set-permissions/', set_custom_role_permissions, name='set_custom_role_permissions'),
    path('custom-roles/view-permissions/', get_custom_role_permissions), # 'custom-roles/view-permissions/?role_name=teacher' to view permissions
    path('custom-roles/assign-to-user/', assign_custom_role_to_user, name='assign_custom_role_to_user'),
    path('user/permissions/', get_current_user_permissions, name='get_current_user_permissions'),   #My permissions
    path('custom-role/users/', list_users_by_custom_role),
    #path('register-custom-user/', register_custom_user, name='register_custom_user'),   #pending
    path('custom-user/register-user/', custom_user_register_user, name='custom_user_register_user'),
    path('custom-roles/<str:role_name>/delete/', views.delete_custom_role, name='delete_custom_role'),
    path('users/<str:user_id>/', view_user_details, name='view_user_details'),   # View details of a specific user
    path('api/users/me/', get_my_details, name='get_my_details'),    # View details of the currently logged-in user
    path('api/users/role/<str:role_name>/', view_users_under_custom_role, name='view_users_under_custom_role'),
    
    path('questions/summary/', views.questions_summary, name='questions_summary'),
    path("flashcards/review/due/", DueReviewFlashcardsView.as_view(), name="due-review-flashcards"),

    path('backup/create/', backup_mongodb, name='backup-create'),
    path('backup/restore/', restore_mongodb, name='backup-restore'),

    # path('permissions/user/set/', set_user_permission),
    # path('permissions/user/delete/<str:user_id>/', delete_user_permission),


] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)