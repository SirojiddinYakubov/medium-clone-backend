from django.core.mail import EmailMessage
from django.conf import settings
from django.template.loader import render_to_string


class Email:
    @staticmethod
    def send_email(user, code):

        subject = 'Welcome to Our Service!'
        message = render_to_string('emails/email_template.html', {
            'user': user,
            'code': code
        })

        email = EmailMessage(
            subject,
            message,
            settings.EMAIL_HOST_USER,
            [settings.EMAIL_HOST_USER]
        )
        email.content_subtype = 'html'
        email.send(fail_silently=False)
