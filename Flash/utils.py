import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from django.conf import settings
from .models import CustomRole, CustomRolePermission, User, OneTimePassword
from datetime import timedelta
from django.utils.timezone import now
import logging
logger = logging.getLogger(__name__)


def send_email(subject, body, to_email):
    """
    Sends an email using SMTP.

    Parameters:
    - subject: Subject of the email
    - body: Body of the email
    - to_email: Recipient's email address
    """
    # Create message container
    msg = MIMEMultipart()
    msg['From'] = settings.DEFAULT_FROM_EMAIL
    msg['To'] = to_email
    msg['Subject'] = subject

    # Attach the email body
    msg.attach(MIMEText(body, 'plain'))

    try:
        # Connect to the SMTP server
        with smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT) as server:
            server.starttls()  # Upgrade the connection to a secure encrypted SSL/TTLS connection
            server.login(settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD)  # Login to the SMTP server
            server.sendmail(settings.DEFAULT_FROM_EMAIL, to_email, msg.as_string())  # Send the email
        logger.info(f"Email sent successfully to {to_email}")
    except Exception as e:
        logger.error(f"Failed to send email to {to_email}: {str(e)}")

def send_code_to_user(email):
    subject = "One Time Passcode for Email Verification"
    otp = generate_otp()
    body = f"Hi, use the passcode {otp} to verify your email. This code is valid for 1 minute."

    user = User.objects.get(email=email)
    otp_obj, created = OneTimePassword.objects.get_or_create(user=user)

    # Check if 1 minute has passed since the last OTP was sent
    if otp_obj.last_sent_at and now() < otp_obj.last_sent_at + timedelta(minutes=1):
        raise ValueError("You must wait 1 minute before requesting another OTP.")

    # Update the OTP and last_sent_at timestamp
    otp_obj.code = otp
    otp_obj.created_at = now()
    otp_obj.last_sent_at = now()
    otp_obj.save()

    send_email(subject, body, email)

def generate_otp():
    """
    Generates a 6-digit OTP code.

    Returns:
    - OTP code as a string
    """
    import random
    return "".join([str(random.randint(0, 9)) for _ in range(6)])


def send_normal_email(data):
    """
    Sends a normal email with the given data.

    Parameters:
    - data: Dictionary containing 'email_subject', 'email_body', and 'to_email'
    """
    subject = data.get('email_subject')
    body = data.get('email_body')
    to_email = data.get('to_email')
    
    send_email(subject, body, to_email)



from .models import UserPermission




def has_permission(user, permission):
    role = user.role

    print(f"🔍 Checking permission: {permission} for role: {role}")

    # ✅ Admins get all permissions
    if role == "admin":
        print("✅ Admin has all permissions by default.")
        return True
    



    # # 1️⃣ Check for user-specific override
    # try:
    #     user_perm = UserPermission.objects.get(user=user)
    #     return getattr(user_perm, permission, False)
    # except UserPermission.DoesNotExist:
    #     pass



    # ✅ Try role-level permission
    try:
        role_perm = UserPermission.objects.get(role=role, user=None)
        result = getattr(role_perm, permission, False)
        print(f"🧾 Found role permission: {permission} = {result}")
        return result
    except UserPermission.DoesNotExist:
        print("❌ Role permission not found.")
        #return False
        pass

    # Check for custom role
    try:
        custom_role = CustomRole.objects.get(name=role)
        custom_perm = CustomRolePermission.objects.get(role=custom_role)
        return getattr(custom_perm, permission, False)
    except (CustomRole.DoesNotExist, CustomRolePermission.DoesNotExist):
        return False
    
    
def get_all_descendant_folder_ids(folder):
    """
    Recursively collect the IDs of a folder and all its subfolders.
    """
    from .models import Folder
    all_folders = Folder.objects.all().values("id", "parent_id")
    folder_ids = set()

    def recurse(fid):
        folder_ids.add(fid)
        for f in all_folders:
            if f["parent_id"] == fid:
                recurse(f["id"])

    recurse(folder.id)
    return list(folder_ids)


from .models import ReviewSettings

def sr_enabled_for(user_id: str) -> bool:
    return ReviewSettings.objects.filter(created_by=user_id).exists()









    