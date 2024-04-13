import requests
from .forms import RegistrationForm, PasswordResetForm, CustomPasswordResetForm
from .models import Account, PasswordHistory, ResetPasswordToken, GoogleWalletPass, AppleWalletPassAccountID, StatusChoices, AccessTiers
from .utils import generate_token
from .validators import validate_password_history, password_history_archiver
from datetime import timedelta
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.sites.shortcuts import get_current_site
from django.core.exceptions import ValidationError
from django.core.validators import EmailValidator
from django.http import HttpResponse, HttpResponseGone
from django.shortcuts import render, redirect
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import timezone
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.safestring import mark_safe
from django.views import View
from redmail import gmail
from passbook.models import Pass, Generic, Location
from .utils import load_public_key, generate_random_serial_number, generate_random_message
from django_walletpass.models import PassBuilder
from django.dispatch import receiver
from django_walletpass.classviews import PASS_REGISTERED, PASS_UNREGISTERED
import django_walletpass.crypto as crypto
import secrets
import uuid
import logging
from django_walletpass.services import PushBackend  # Adjust the import according to your project structure
from django_walletpass.models import Pass, Registration
from GooglePass.demo_generic import DemoGeneric
from GooglePass.demo_loyalty import DemoLoyalty
from datetime import datetime
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from django.db.models import Q

logger = logging.getLogger(__name__)

gmail.password = settings.EMAIL_HOST_PASSWORD
gmail.username = settings.EMAIL_HOST_USER

style_attributes = (
    "display: inline-block;"
    "background-color: #FF5733;"
    "color: white;"
    "padding: 8px 15px;"
    "text-decoration: none;"
    "border-radius: 4px;"
    "cursor: pointer;"
    "border: none;"
)

def generate_activation_token(user):
    token_generator = PasswordResetTokenGenerator()
    token = token_generator.make_token(user)
    token = f"{token}::::{user.token_version}"  # Append user's token_version
    return token

def validate_activation_token(user, token):
    token_generator = PasswordResetTokenGenerator()
    parts = token.split('::::')
    if len(parts) == 2:
        token, token_version = parts
        if token_generator.check_token(user, token) and int(token_version) == user.token_version:
            return True
    return False

def resend_activation_email(request, username):
    try:
        user = Account.objects.get(username=username)
        if not user.is_active:
            email = user.email
            current_site=get_current_site(request)
            email_subject="Senity Security Systems - Account activation"
            user.token_version += 1
            user.save()
            token_ = generate_activation_token(user)
            context_reg_data = {
                "User":user,
                "domain":current_site.domain,
                "uidb64":urlsafe_base64_encode(force_bytes(user.pk)),
                "token": token_,
                "current_year": datetime.now().year
            }
            message = render_to_string("activate.html", context_reg_data)

            gmail.send(
                subject= email_subject,
                receivers=[email],
                html=message,
                #Embedded contents
                body_params={
                    "User": user,
                    "domain": current_site.domain,
                    "uidb64": urlsafe_base64_encode(force_bytes(user.pk)),
                    "token": token_
                },
            )
            messages.success(request, "Activation email has been resent. Please check your inbox.")
    except Account.DoesNotExist:
        messages.error(request, "User does not exist.")
    return redirect("login")  # Assuming "login" is the name of the login view

def login_user(request):
    #This is required.
    resend_url = None
    if request.user.is_authenticated:
        return redirect("dashboard")
    else:
        if request.method == "POST":

            username = request.POST.get("username")
            password = request.POST.get("password")

            user = authenticate(request, username=username, password=password)

            if user is not None:
                login(request, user)
                return redirect("dashboard")
            else:
                try:
                    user = Account.objects.get(username=username)
                    if not user.is_active:
                        resend_url = reverse('resend_activation_email', args=[username])

                        error_msg = f"User is not activated. Please, check your email and activate your account or click on the resend activation link."
                        messages.error(request, mark_safe(error_msg))
                    else:
                        messages.error(
                            request, "Username or Password is incorrect!")
                except Account.DoesNotExist:
                    messages.error(
                        request, "Username does not exist or deleted!")
    messages_list = list(messages.get_messages(request))
    render_dict = {
        'infoMessages': messages_list,
        'site_key': settings.RECAPTCHA_SITE_KEY,
        "show_resend_link": resend_url
    }
    return render(request, "login.html", render_dict)

def register_user(request):
    if request.user.is_authenticated:
        return redirect("dashboard")
    else:
        form = RegistrationForm()
        context = {"form": form}

        if request.method == "POST":

            form = RegistrationForm(request.POST)
            secret_key = settings.RECAPTCHA_SECRET_KEY

            # captcha verification
            data = request.POST
            data = {
                'response': data.get('g-recaptcha-response'),
                'secret': secret_key
            }
            resp = requests.post(
                'https://www.google.com/recaptcha/api/siteverify', data=data)
            result_json = resp.json()

            print(result_json)

            

            if not result_json.get('success'):
                messages.error(
                    request, f"Registration failed. We could not verify that you are human. Please try again!\n")
                return render(request, 'register.html', {**context,'is_robot': True})
            # end captcha verification

            if form.is_valid():
                email = form.cleaned_data.get("email")
                username = form.cleaned_data.get("username")
                raw_password = form.cleaned_data.get("password1")
                user = Account.objects.create_user(email, username, raw_password)
                user.is_active = False
                # Save the new password in the password history
                try:
                    password_history = PasswordHistory(
                        user=user, password=user.password)
                    password_history.save()
                except ValidationError as e:
                    form.add_error(None, e)
                    messages_list = list(messages.get_messages(request))
                    render_dict = {
                        **context,
                        'site_key': settings.RECAPTCHA_SITE_KEY,
                        'infoMessages': messages_list
                    }
                    return render(request,
                        'register.html',
                        render_dict,
                    )
                #Keep only the latest 5 passwords of the user
                password_history_archiver(user)
                user.save()

                messages.success(
                    request, f"Account created for {username}\n")
                messages.success(
                    request, f"An email sent to {email}\nPlease, activate your account!")

                current_site=get_current_site(request)
                email_subject="Senity Security Systems - Account activation"
                token_ = generate_activation_token(user)
                context_reg_data = {
                    "User":user,
                    "domain":current_site.domain,
                    "uidb64":urlsafe_base64_encode(force_bytes(user.pk)),
                    "token": token_,
                    "current_year": datetime.now().year
                }
                message = render_to_string("activate.html", context_reg_data)

                gmail.send(
                    subject= email_subject,
                    receivers=[email],
                    html=message,
                    #Embedded contents
                    body_params={
                        "User": user,
                        "domain": current_site.domain,
                        "uidb64": urlsafe_base64_encode(force_bytes(user.pk)),
                        "token": token_
                    },
                )
                return redirect("login")
            else:
                for error in list(form.errors.values()):
                    messages.error(request, error)
    messages_list = list(messages.get_messages(request))
    render_dict = {
        **context,
        'site_key': settings.RECAPTCHA_SITE_KEY,
        'infoMessages': messages_list
    }
    return render(request,
        'register.html',
        render_dict,
        
    )

@login_required(login_url='login')
def logout_user(request):
    logout(request)
    return redirect("login")

def build_pkpass(user):
    file_name = f"{uuid.uuid1()}.pkpass"
    builder = PassBuilder(directory = settings.APPLE_PASS_JSON_PATH)
    builder.pass_data_required["serialNumber"] = secrets.token_urlsafe(24)
    builder.pass_data_required["authenticationToken"] = crypto.gen_random_token()
    builder.pass_data_required["webServiceURL"] = "https://senitysecuritysystems.com/api/passes/"
    builder.pass_data["nfc"]["message"] = secrets.token_hex(4)

    if user.is_admin:
        builder.pass_data["generic"]["headerFields"][0]["value"] = AccessTiers.ELITE
        access_tier = AccessTiers.ELITE
    else:
        builder.pass_data["generic"]["headerFields"][0]["value"] = AccessTiers.STANDARD
        access_tier = AccessTiers.STANDARD
    builder.pass_data["generic"]["secondaryFields"][0]["value"] = user.username
    builder.pass_data["generic"]["auxiliaryFields"][0]["value"] = builder.pass_data["nfc"]["message"].upper()
    builder.pass_data["generic"]["auxiliaryFields"][1]["value"] = datetime.now().year
    builder.pass_data["generic"]["auxiliaryFields"][2]["value"] = "ACTIVE"

    builder.pass_data["generic"]["backFields"][0]["value"] = builder.pass_data_required["webServiceURL"]
    builder.pass_data["generic"]["backFields"][1]["value"] = builder.pass_data_required["serialNumber"]
    builder.pass_data["generic"]["backFields"][2]["value"] = builder.pass_data_required["authenticationToken"]
    builder.pass_data["generic"]["backFields"][3]["value"] = file_name
    builder.pass_data["generic"]["backFields"][4]["value"] = builder.pass_data["nfc"]["message"]
    pkpass_content = builder.build()

    pass_instance = builder.write_to_model(file_name = file_name)
    pass_instance.save()

    ApplePassAccount = AppleWalletPassAccountID(account = user, pay_load = builder.pass_data["nfc"]["message"], pass_id = pass_instance.id, access_tier = access_tier)
    ApplePassAccount.save()

    response = HttpResponse(pkpass_content, content_type="application/vnd.apple.pkpass")
    response['Content-Disposition'] = 'attachment; filename="senity.pkpass"'
    return response

def send_push_notification(request, id):
    try:
        # Step 1: Retrieve the Pass Instance
        pass_instance = Pass.objects.get(id=id)
        file_name = pass_instance.data.name.split('/')[-1]

        # Step 2: Update the Pass
        pass_builder = pass_instance.get_pass_builder()
        pass_builder.pass_data["nfc"]["message"] = "1111"
        pass_builder.pass_data["lastUpdated"] = timezone.now().isoformat()
        pass_builder.pass_data["generic"]["backFields"][4]["value"] = pass_builder.pass_data["nfc"]["message"]
        pass_builder.pass_data["generic"]["primaryFields"][0]["changeMessage"] = f"Your NFC message has been updated to {pass_builder.pass_data['nfc']['message']}."
        pass_builder.pass_data["generic"]["auxiliaryFields"][0]["value"] = "1111"
        pass_builder.pass_data["generic"]["auxiliaryFields"][2]["value"] = "REJECTED"
        # Step 3: Rebuild and Save the Pass
        pass_builder.build()
        pass_builder.write_to_model(file_name = file_name, instance=pass_instance)
        pass_instance.save()

        # Step 4: Send a Push Notification
        push_backend = PushBackend()
        for registration in pass_instance.get_registrations():
            push_backend.push_notification_from_instance(registration)
            AppleWalletPassAccountID.objects.filter(pass_id=id).update(status=StatusChoices.UPDATED, pay_load = "1111")
            messages.success(request, "Push notification sent successfully.")
            logger.debug(f'[DEBUG]: Successfully sent revocation notifications for {id}.')
    except Pass.DoesNotExist:
        messages.error(request, f"Pass not found with the given ID: {id}")
        logger.debug(f"[DEBUG]: Pass not found with the given ID: {id}.")
    except Exception as e:
        messages.error(request, f"An error occurred: {e}")
        logger.debug(f"[DEBUG]: An error occurred: {e}")
    return redirect('dashboard')

def build_google_pass():
    _issuer_id = settings.GOOGLE_ISSUER_ID
    _class_suffix = secrets.token_urlsafe(24)
    _object_suffix  = secrets.token_urlsafe(24)
    generic_pass = DemoGeneric()
    logger.debug(f"[DEBUG]: _issuer_id: {_issuer_id}")
    jwt_link  = generic_pass.create_jwt_new_objects(
        issuer_id = _issuer_id,
        class_suffix = _class_suffix,
        object_suffix = _object_suffix,
        user_name = "Daniel Pal",
        pay_load=secrets.token_hex(4),
        date_time = datetime.now().strftime("%Y"))
    logger.debug(f"[DEBUG]: jwt_link: {jwt_link}")
    return jwt_link

def build_private_generic_google_pass():

    return DemoGeneric.create_jwt_private_generic_pass(issuer_id = settings.GOOGLE_ISSUER_ID,
                                key_file_path = settings.GOOGLE_APPLICATION_CREDENTIALS,
                                object_suffix = secrets.token_urlsafe(24),
                               user_name = "Daniel Pal", pay_load = secrets.token_hex(4),
                               date_time = datetime.now().strftime("%Y"))

def build_loyalty_google_pass(issuer_id, class_suffix, object_suffix, pay_load, user_name, access_tier):
    loyalty_pass = DemoLoyalty()
    loyalty_object = loyalty_pass.create_object(issuer_id = issuer_id, class_suffix = class_suffix, object_suffix = object_suffix, user_name=user_name, pay_load=pay_load, date_time = datetime.now().strftime("%Y"), access_tier = access_tier)
    jwt_link, token = loyalty_pass.create_jwt_existing_objects(issuer_id, loyalty_object, class_suffix)
    return jwt_link, token

@login_required(login_url='login')
def dashboard_user(request):
    if request.method == "POST":
        if 'generate_pass' in request.POST:
            return build_pkpass(request.user)
        elif 'send_notification' in request.POST:
            apple_pass_account = AppleWalletPassAccountID.objects.filter(account=request.user).order_by('-pass_id').first()
            if apple_pass_account:
                pass_id = apple_pass_account.pass_id
                return send_push_notification(request, pass_id)
        elif "generate_google_pass" in request.POST:
            _issuer_id = settings.GOOGLE_ISSUER_ID
            _object_suffix = secrets.token_urlsafe(24)
            _class_suffix = settings.GOOGLE_PASS_CLASS
            _pay_load = secrets.token_hex(4)
            user_name = request.user.username
            if request.user.is_admin:
                access_tier = AccessTiers.ELITE
                
            else:
                access_tier = AccessTiers.STANDARD
            logger.debug(f"[DEBUG]: accesstier: {access_tier}")
            jwt_link, token = build_loyalty_google_pass(_issuer_id, _class_suffix, _object_suffix, _pay_load, user_name, access_tier)

            #Store the actual user's pass
            logger.debug(f"[DEBUG]: stored pass")
            GoogleWalletPass.objects.create(
                account=request.user,
                issuer_id=_issuer_id,
                class_suffix=_class_suffix,
                object_suffix=_object_suffix,
                pay_load=_pay_load,
                jwt_link=jwt_link,
                token=token,
                status='CREATED',
                access_tier = access_tier
            )
            request.session['google_pass_link'] = jwt_link  # Store in session
            return redirect('dashboard')
        elif "send_notification_google" in request.POST:
            _issuer_id = settings.GOOGLE_ISSUER_ID
            c_user = request.user
            logger.debug(f"[DEBUG]: f'{c_user.id}'" )
            pass_record = GoogleWalletPass.objects.filter(
                Q(account=c_user) & 
                (Q(status='SAVED') | Q(status='UPDATED'))
            ).order_by('-date_created').first()
            if pass_record is not None:
                loyalty_pass_instance = DemoLoyalty()
                _objt_suffix = pass_record.object_suffix
                resp, status = loyalty_pass_instance.patch_object(_issuer_id, _objt_suffix, "1111", "1111", "REJECTED", "uid", "status")
                logger.debug(f"[DEBUG]: Googlepass patch response f'{resp}'")
                if status == "OK":
                    pass_record.pay_load = "1111"
                    pass_record.status = StatusChoices.UPDATED
                    pass_record.save()
    google_pass_link = request.session.pop('google_pass_link', None)  # Retrieve and remove from session

    return render(request, "dashboard.html", {'google_pass_link': google_pass_link})

@csrf_exempt
def google_wallet_callback(request):
    logger.debug(f"[DEBUG]: Googlepass callback called")
    try:
        body_data = json.loads(request.body.decode('utf-8'))
        signed_message_json = body_data.get('signedMessage')
        logger.debug(f"[DEBUG]: Googlepass Callback")
        if signed_message_json:
            logger.debug(f"[DEBUG]: Googlepass signed_message_json")
            signed_message = json.loads(signed_message_json)
            event_type = signed_message.get('eventType')
            class_id_with_issuer = signed_message.get('classId')
            object_id_with_issuer = signed_message.get('objectId')
            
            # Leválasztjuk az issuer ID-t
            _, class_suffix = class_id_with_issuer.split('.', 1)
            _, object_suffix = object_id_with_issuer.split('.', 1)

            if event_type == 'save':
                logger.debug(f"[DEBUG]: Googlepass save")
                # Megkeressük és frissítjük az adatbázisban lévő rekordot
                pass_record = GoogleWalletPass.objects.filter(class_suffix=class_suffix, object_suffix=object_suffix).first()
                if pass_record:
                    logger.debug(f"[DEBUG]: Googlepass pass_record")
                    pass_record.status = 'SAVED'  # Feltételezve, hogy van egy 'SAVED' állapot
                    pass_record.save()
                    return JsonResponse({'status': 'success', 'message': 'Pass updated to SAVED'})
                else:
                    logger.debug(f"[DEBUG]: Googlepass Nincs")
                    return JsonResponse({'status': 'error', 'message': 'Pass not found'}, status=404)

            elif event_type == 'del':
                logger.debug(f"[DEBUG]: Googlepass delete")
                # Megkeressük és töröljük a rekordot
                #pass_record = GoogleWalletPass.objects.filter(class_suffix=class_suffix, object_suffix=object_suffix).delete()
                pass_record = GoogleWalletPass.objects.filter(class_suffix=class_suffix, object_suffix=object_suffix).first()
                pass_record.status = "REMOVED"
                pass_record.save()
                return JsonResponse({'status': 'success', 'message': 'User removed the Pass'})

            else:
                logger.debug(f"[DEBUG]: Googlepass vmi mas event")
                return JsonResponse({'status': 'error', 'message': 'Unhandled event type'}, status=400)
        else:
            logger.debug(f"[DEBUG]: Googlepass not signed")
            return JsonResponse({'status': 'error', 'message': 'signedMessage not found'}, status=400)

    except json.JSONDecodeError as e:
        return JsonResponse({'status': 'error', 'message': 'Invalid JSON format'}, status=400)
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': 'Unexpected error occurred'}, status=500)


@receiver(PASS_REGISTERED)
def pass_registered(sender, **kwargs):
    logger.debug("[DEBUG]: Pass successfully registered!")
    logger.debug(f"[DEBUG]: sender data: {sender}")
    AppleWalletPassAccountID.objects.filter(pass_id=sender.id).update(status=StatusChoices.ACTIVATED)

@receiver(PASS_UNREGISTERED)
def pass_unregistered(sender, **kwargs):
    logger.debug("[DEBUG]: Pass successfully un-registered!")
    logger.debug(f"[DEBUG]: sender data: {sender}")
    AppleWalletPassAccountID.objects.filter(pass_id=sender.id).update(status=StatusChoices.REMOVED)


@login_required(login_url='login')
def generate_pass(request):
    return HttpResponse("Hello")


def reset_password(request):
    if request.method == "GET":
        form = PasswordResetForm()
        context = {"form": form}
    if request.method == "POST":
        form = PasswordResetForm(request.POST)
        context = {"form": form}
        secret_key = settings.RECAPTCHA_SECRET_KEY

        # captcha verification
        data = request.POST
        data = {
            'response': data.get('g-recaptcha-response'),
            'secret': secret_key
        }
        resp = requests.post(
            'https://www.google.com/recaptcha/api/siteverify', data=data)
        result_json = resp.json()

        if not result_json.get('success'):
            messages.error(
                request, f"Password reset failed. We could not verify that you are human. Please try again!\n")
            return render(request, 'password_reset.html', {**context, 'is_robot': True})
            # end captcha verification
        if form.is_valid():
            email = form.cleaned_data.get("email")
            email_validator = EmailValidator()
            try:
                email_validator(email)
            except ValidationError:
                messages.error(
                    request, f"Invalid email address!\n")
                return render(request, 'password_reset.html', {**context, 'is_robot': False})

            user = Account.objects.filter(email=email).first()
            if user:
                if not user.is_active:
                    messages.error(request, f"Password reset is not allowed for non-activated accounts!\n")
                    messages.error(request, f"Please, activate your account!\n")
                    messages_list = list(messages.get_messages(request))
                    return render(request, 'password_reset.html', {**context, 'is_robot': False, 'infoMessages': messages_list})

                # Update is_password_reset flag
                user.is_password_reset = True
                user.save()
                # Generate a new token if no valid, unused token exists
                token = generate_activation_token(user)

                domain = get_current_site(request).domain
                context_reg_data = {
                    "User": user,
                    "domain": domain,
                    "uidb64": urlsafe_base64_encode(force_bytes(user.pk)),
                    "token": token,
                    "current_year": datetime.now().year
                }

                message = render_to_string(
                    'password_reset_email.html', context_reg_data)
                gmail.send(
                    subject='Password Reset Request',
                    receivers=[email],
                    html=message,
                    # Embedded contents
                    body_params={
                        "User": user,
                        "domain": domain,
                        "uidb64": urlsafe_base64_encode(force_bytes(user.pk)),
                        "token": token
                    },
                )
                messages.success(
                    request, f"Password reset email sent.\n")
                return redirect('login')
            else:
                messages.error(
                    request, f"This email address is not associated with any account.\n")
                return redirect('resetPass')

        else:
            for error in list(form.errors.values()):
                messages.error(request, error)
    messages_list = list(messages.get_messages(request))
    render_dict = {
        **context,
        'site_key': settings.RECAPTCHA_SITE_KEY,
        'infoMessages': messages_list
    }
    return render(request,
                  'password_reset.html',
                  render_dict,
                  )
class ActivateAccountView(View):
    def get(self, request, uidb64, token):
        try:
            uid=force_text(urlsafe_base64_decode(uidb64))
            user=Account.objects.get(pk=uid)
        except:
            user=None
            
        if user is not None and validate_activation_token(user, token):
            user.is_active=True
            user.save()
            messages.success(request, f"Your Account activated successfully in the system!\n")
            return redirect("login")
        return render(request, "activate_failed.html", status=401)


class ResetPasswordView(View):
    template_name = 'confirm_reset_password.html'

    def get(self, request, uidb64, token):
        form = CustomPasswordResetForm()
        context = {"form": form, "uidb64": uidb64, "token": token}
        try:
            uid = force_text(urlsafe_base64_decode(uidb64))
            user = Account.objects.get(pk=uid)
        except:
            user = None

        if user is not None and validate_activation_token(user, token):
            messages_list = list(messages.get_messages(request))
            render_dict = {
                **context,
                'site_key': settings.RECAPTCHA_SITE_KEY,
                'infoMessages': messages_list
            }
            return render(request, self.template_name, render_dict)
        elif not (validate_activation_token(user, token)):
            #delete the expired token from the DB.
            messages.error(
                request, "Invalid or expired password reset token.")
            return redirect('login')

    def post(self, request, uidb64, token):
        form = CustomPasswordResetForm(request.POST)
        context = {"form": form, "uidb64": uidb64, "token": token}
        secret_key = settings.RECAPTCHA_SECRET_KEY
        try:
            uid = force_text(urlsafe_base64_decode(uidb64))
            user = Account.objects.get(pk=uid)
        except:
            user = None

        messages_list = list(messages.get_messages(request))

        if user is not None and validate_activation_token(user, token):

            # captcha verification
            data = request.POST
            data = {
                'response': data.get('g-recaptcha-response'),
                'secret': secret_key
            }
            resp = requests.post(
                'https://www.google.com/recaptcha/api/siteverify', data=data)
            result_json = resp.json()

            print(result_json)

            if not result_json.get('success'):
                messages.error(
                    request, f"Password reset failed. We could not verify that you are human. Please try again!\n")
                return redirect(request, 'password_reset.html', {**context, 'is_robot': True})

            if form.is_valid():
                # check if the new password is different then the old 5 one.
                updated_password = form.cleaned_data.get("new_password1")
                try:
                    validate_password_history(user, updated_password)
                except ValidationError as e:
                    error_message = ''.join(e.message)
                    messages.error(request, error_message)
                    messages_list = list(messages.get_messages(request))
                    render_dict = {
                        **context,
                        'site_key': settings.RECAPTCHA_SITE_KEY,
                        'infoMessages': messages_list
                    }
                    return render(request, self.template_name, render_dict)

                user.set_password(updated_password)
                user.is_password_reset = False
                user.save()

                # Save the new password in the password history
                password_history = PasswordHistory(
                    user=user, password=user.password)
                password_history.save()
                # Keep only the latest 5 passwords of the user
                password_history_archiver(user)

                messages.success(request, f"Password reset was successful!\n")
            else:
                for error in list(form.errors.values()):
                    messages.error(request, error)
                messages_list = list(messages.get_messages(request))
                render_dict = {
                    **context,
                    'site_key': settings.RECAPTCHA_SITE_KEY,
                    'infoMessages': messages_list
                }
                return render(request, self.template_name, render_dict)
        elif validate_activation_token(user, token):
            messages.error(
                request, f"Invalid or expired password reset token.")
            return redirect('login')

        return redirect('login')

class RobotsTxtView(View):
    def get(self, request, *args, **kwargs):
        lines = [
            "User-agent: Google-Valuables",
            "Allow: /google/api/passes/",
            "User-agent: Googlebot",
            "Allow: /google/api/passes/"
        ]
        return HttpResponse("\n".join(lines), content_type="text/plain")
