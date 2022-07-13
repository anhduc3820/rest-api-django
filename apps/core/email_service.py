import logging
from django.core.mail import EmailMessage
from apps.users import utils as user_utils
from apps.core import consts

_logger = logging.getLogger(__name__)


class EmailService:
    @staticmethod
    def send_email(
        *,
        from_email: str = None,
        subject: str,
        body: str,
        to_emails: list,
        bcc: list = None,
        cc: list = None,
        reply_to: list = None,
    ) -> int:
        _logger.info(
            f"Start sending email, from_email: {from_email}, to_emails: {to_emails},"
            f" bcc: {bcc}, cc: {cc}, reply_to: {reply_to}"
        )
        email = EmailMessage(
            subject,
            body,
            from_email=from_email,
            to=to_emails,
            bcc=bcc,
            cc=cc,
            reply_to=reply_to,
        )
        email.content_subtype = "html"
        num_sent = email.send()
        _logger.info(f"Finish send email, num_sent: {num_sent}")
        return num_sent


def send_save_email(
    subject: str,
    body_html: str,
    from_email: str,
    email: str,
    company_id: int,
    model: str,
    res_id: int,
    bcc: str = None,
    cc: list = None,
    reply_to: str = None,
):
    """
    When calling the send email function, perform the addition to the mail_message
    and mail_mail tables with mail_message_id is mail_message.id
    """
    try:
        list_bcc = [item.strip() for item in bcc.split(",")] if bcc else None
        list_reply_to = [reply_to] if reply_to else None
        EmailService.send_email(
            subject=subject,
            body=body_html,
            from_email=from_email,
            to_emails=[email],
            bcc=list_bcc,
            cc=cc,
            reply_to=list_reply_to,
        )
        company = user_utils.get_company(company_id)
        message = user_utils.save_mail_message(
            subject=subject,
            body=body_html,
            res_id=res_id,
            email_from=from_email,
            author_id=company.partner_id,
            model=model,
        )
        user_utils.save_mail_mail(
            mail_message_id=message.id,
            body_html=body_html,
            email_to=email,
            state=consts.StateEmail.SENT.value,
            company_id=company_id,
        )
    except Exception as err:
        _logger.exception(
            f"Failed send email from email: {from_email}, to email: {email}"
        )
        company = user_utils.get_company(company_id)
        message = user_utils.save_mail_message(
            subject=subject,
            body=body_html,
            res_id=res_id,
            email_from=from_email,
            author_id=company.partner_id,
            model=model,
        )
        user_utils.save_mail_mail(
            mail_message_id=message.id,
            body_html=body_html,
            email_to=email,
            state=consts.StateEmail.EXCEPTION.value,
            failure_reason=err,
            company_id=company_id,
        )
