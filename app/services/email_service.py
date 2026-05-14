# app/services/email_service.py
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
from typing import Optional, Dict, Any
from datetime import datetime
import httpx

from app.config import settings

logger = logging.getLogger(__name__)


class EmailService:
    """
    Servicio de envio de emails.
    """
    
    def __init__(self):
        self.sendgrid_api_key = settings.sendgrid_api_key
        self.sendgrid_from_email = settings.sendgrid_from_email
        self.sendgrid_from_name = settings.sendgrid_from_name
        
        self.smtp_host = settings.smtp_host
        self.smtp_port = settings.smtp_port
        self.smtp_user = settings.smtp_user
        self.smtp_password = settings.smtp_password
        self.smtp_from = settings.smtp_from
        self.smtp_from_name = settings.smtp_from_name
        
        self.use_sendgrid = bool(self.sendgrid_api_key)
        self.use_smtp = bool(self.smtp_user and self.smtp_password)
        
        logger.info("=" * 50)
        logger.info("EmailService initialized")
        logger.info(f"   SendGrid: {'YES' if self.use_sendgrid else 'NO'}")
        logger.info(f"   SMTP: {'YES' if self.use_smtp else 'NO'}")
        logger.info("=" * 50)
    
    async def send_email(
        self,
        to_email: str,
        subject: str,
        html_content: str,
        text_content: Optional[str] = None
    ) -> bool:
        """Send email using SendGrid or SMTP fallback."""
        if text_content is None:
            text_content = self._html_to_text(html_content)
        
        if self.use_sendgrid:
            success = await self._send_via_sendgrid(to_email, subject, html_content, text_content)
            if success:
                logger.info(f"Email sent to {to_email} via SendGrid")
                return True
            logger.warning("SendGrid failed, trying SMTP...")
        
        if self.use_smtp:
            success = await self._send_via_smtp(to_email, subject, html_content, text_content)
            if success:
                logger.info(f"Email sent to {to_email} via SMTP")
                return True
        
        logger.warning(f"Could not send email to {to_email}. Logging content:")
        logger.info(f"[DEV] To: {to_email}")
        logger.info(f"[DEV] Subject: {subject}")
        logger.info(f"[DEV] Content: {text_content[:200]}...")
        
        return False
    
    async def _send_via_sendgrid(
        self,
        to_email: str,
        subject: str,
        html_content: str,
        text_content: str
    ) -> bool:
        """Send email via SendGrid API."""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    "https://api.sendgrid.com/v3/mail/send",
                    headers={
                        "Authorization": f"Bearer {self.sendgrid_api_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "personalizations": [{"to": [{"email": to_email}]}],
                        "from": {"email": self.sendgrid_from_email, "name": self.sendgrid_from_name},
                        "subject": subject,
                        "content": [
                            {"type": "text/plain", "value": text_content},
                            {"type": "text/html", "value": html_content}
                        ]
                    }
                )
                return response.status_code == 202
        except Exception as e:
            logger.error(f"SendGrid error: {e}")
            return False
    
    async def _send_via_smtp(
        self,
        to_email: str,
        subject: str,
        html_content: str,
        text_content: str
    ) -> bool:
        """Send email via SMTP."""
        try:
            msg = MIMEMultipart('alternative')
            msg["From"] = f"{self.smtp_from_name} <{self.smtp_from}>"
            msg["To"] = to_email
            msg["Subject"] = subject
            
            msg.attach(MIMEText(text_content, 'plain', 'utf-8'))
            msg.attach(MIMEText(html_content, 'html', 'utf-8'))
            
            if self.smtp_port == 465:
                server = smtplib.SMTP_SSL(self.smtp_host, self.smtp_port, timeout=30)
            else:
                server = smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=30)
                server.starttls()
            
            server.login(self.smtp_user, self.smtp_password)
            server.send_message(msg)
            server.quit()
            
            return True
            
        except Exception as e:
            logger.error(f"SMTP error: {e}")
            return False
    
    def _html_to_text(self, html: str) -> str:
        """Convert HTML to plain text."""
        import re
        text = re.sub(r'<style[^>]*>.*?</style>', '', html, flags=re.DOTALL)
        text = re.sub(r'<[^>]+>', ' ', text)
        text = re.sub(r'\s+', ' ', text)
        return text.strip()
    
    async def send_otp_email(self, email: str, code: str) -> bool:
        """Send OTP code for authentication."""
        subject = f"Your QuickNote verification code: {code}"
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>QuickNote Verification Code</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #f4f4f4; padding: 20px; }}
        .container {{ max-width: 600px; margin: 0 auto; background: white; border-radius: 16px; overflow: hidden; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; }}
        .header h1 {{ color: white; margin: 0; }}
        .content {{ padding: 30px; text-align: center; }}
        .code-box {{ background: #f8f9fa; border: 2px dashed #667eea; border-radius: 12px; padding: 20px; margin: 20px 0; }}
        .code {{ font-size: 48px; font-weight: bold; color: #667eea; letter-spacing: 8px; }}
        .footer {{ background: #f8f9fa; padding: 20px; text-align: center; color: #999; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>QuickNote</h1>
            <p>Your verification code</p>
        </div>
        <div class="content">
            <p>Use the following code to complete your authentication:</p>
            <div class="code-box">
                <span class="code">{code}</span>
            </div>
            <p>This code expires in 10 minutes.</p>
            <p>If you did not request this code, please ignore this message.</p>
        </div>
        <div class="footer">
            <p>QuickNote - Your secure notes space</p>
        </div>
    </div>
</body>
</html>
"""
        
        text_content = f"""
Your QuickNote verification code is: {code}

This code expires in 10 minutes.

If you did not request this code, please ignore this message.

---
QuickNote - Your secure notes space
"""
        
        return await self.send_email(email, subject, html_content, text_content)
    
    async def send_password_change_confirmation(self, email: str, name: str, ip_address: str = None) -> bool:
        """Send password change confirmation email."""
        subject = "Your password has been updated - QuickNote"
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Password Updated - QuickNote</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #f4f4f4; padding: 20px; }}
        .container {{ max-width: 600px; margin: 0 auto; background: white; border-radius: 16px; overflow: hidden; }}
        .header {{ background: linear-gradient(135deg, #10B981 0%, #059669 100%); padding: 30px; text-align: center; }}
        .header h1 {{ color: white; margin: 0; }}
        .content {{ padding: 30px; }}
        .info-box {{ background: #f0fdf4; border-left: 4px solid #10B981; padding: 15px; margin: 20px 0; border-radius: 8px; }}
        .footer {{ background: #f8f9fa; padding: 20px; text-align: center; color: #999; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>QuickNote</h1>
            <p>Password change confirmation</p>
        </div>
        <div class="content">
            <h2>Hello {name}!</h2>
            <p>Your password has been <strong>successfully updated</strong>.</p>
            
            <div class="info-box">
                <strong>Change details:</strong><br>
                ? Date: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}<br>
                ? IP: {ip_address or 'Not recorded'}
            </div>
            
            <p><strong>Didn't make this change?</strong><br>
            If you did not change your password, please contact our support immediately.</p>
        </div>
        <div class="footer">
            <p>QuickNote - Your secure notes space</p>
        </div>
    </div>
</body>
</html>
"""
        
        text_content = f"""
Hello {name},

Your password has been successfully updated.

Change details:
- Date: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}
- IP: {ip_address or 'Not recorded'}

Didn't make this change?
If you did not change your password, please contact our support immediately.

---
QuickNote - Your secure notes space
"""
        
        return await self.send_email(email, subject, html_content, text_content)
    
    async def send_password_expiry_warning(self, email: str, name: str, days_remaining: int) -> bool:
        """Send password expiry warning email."""
        subject = f"Your password will expire in {days_remaining} days - QuickNote"
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Password Expiry Warning - QuickNote</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #f4f4f4; padding: 20px; }}
        .container {{ max-width: 600px; margin: 0 auto; background: white; border-radius: 16px; overflow: hidden; }}
        .header {{ background: linear-gradient(135deg, #F59E0B 0%, #DC2626 100%); padding: 30px; text-align: center; }}
        .header h1 {{ color: white; margin: 0; }}
        .content {{ padding: 30px; }}
        .days {{ font-size: 48px; font-weight: bold; color: #DC2626; text-align: center; margin: 20px 0; }}
        .footer {{ background: #f8f9fa; padding: 20px; text-align: center; color: #999; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>QuickNote</h1>
            <p>Expiry warning</p>
        </div>
        <div class="content">
            <h2>Hello {name}!</h2>
            <p>Your password will expire in:</p>
            
            <div class="days">
                {days_remaining} day{'' if days_remaining == 1 else 's'}
            </div>
            
            <p>We recommend changing your password as soon as possible to keep your account secure.</p>
        </div>
        <div class="footer">
            <p>QuickNote - Your secure notes space</p>
        </div>
    </div>
</body>
</html>
"""
        
        text_content = f"""
Hello {name},

Your password will expire in {days_remaining} day{'' if days_remaining == 1 else 's'}.

We recommend changing your password as soon as possible to keep your account secure.

---
QuickNote - Your secure notes space
"""
        
        return await self.send_email(email, subject, html_content, text_content)
    
    async def send_security_alert(self, email: str, name: str, alert_type: str, details: Dict) -> bool:
        """Send security alert email."""
        alert_titles = {
            "new_device": "New device detected",
            "multiple_failures": "Multiple failed login attempts",
            "password_changed": "Password change detected",
            "suspicious_activity": "Suspicious activity detected"
        }
        
        title = alert_titles.get(alert_type, "Security alert")
        subject = f"Security alert - QuickNote"
        
        details_text = ""
        for key, value in details.items():
            details_text += f"? {key}: {value}<br>"
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Alert - QuickNote</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #f4f4f4; padding: 20px; }}
        .container {{ max-width: 600px; margin: 0 auto; background: white; border-radius: 16px; overflow: hidden; }}
        .header {{ background: linear-gradient(135deg, #EF4444 0%, #DC2626 100%); padding: 30px; text-align: center; }}
        .header h1 {{ color: white; margin: 0; }}
        .content {{ padding: 30px; }}
        .alert-box {{ background: #fef2f2; border-left: 4px solid #EF4444; padding: 15px; margin: 20px 0; border-radius: 8px; }}
        .footer {{ background: #f8f9fa; padding: 20px; text-align: center; color: #999; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>QuickNote</h1>
            <p>Security alert</p>
        </div>
        <div class="content">
            <h2>Hello {name}!</h2>
            <p>We detected the following activity on your account:</p>
            
            <div class="alert-box">
                <strong>{title}</strong><br>
                {details_text}
            </div>
            
            <p><strong>Don't recognize this activity?</strong><br>
            If this wasn't you, we recommend changing your password immediately.</p>
        </div>
        <div class="footer">
            <p>QuickNote - Your secure notes space</p>
        </div>
    </div>
</body>
</html>
"""
        
        text_content = f"""
Hello {name},

Security alert: {title}

Details:
{self._format_details_text(details)}

Don't recognize this activity?
If this wasn't you, we recommend changing your password immediately.

---
QuickNote - Your secure notes space
"""
        
        return await self.send_email(email, subject, html_content, text_content)
    
    def _format_details_text(self, details: Dict) -> str:
        """Format details for plain text."""
        lines = []
        for key, value in details.items():
            lines.append(f"? {key}: {value}")
        return '\n'.join(lines)


async def send_otp_email(email: str, code: str) -> bool:
    """Legacy function for OTP email (maintains compatibility)."""
    service = EmailService()
    return await service.send_otp_email(email, code)


email_service = EmailService()