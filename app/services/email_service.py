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
        logger.info("EmailService inicializado")
        logger.info(f"   SendGrid: {'SI' if self.use_sendgrid else 'NO'}")
        logger.info(f"   SMTP: {'SI' if self.use_smtp else 'NO'}")
        logger.info("=" * 50)
    
    async def send_email(
        self,
        to_email: str,
        subject: str,
        html_content: str,
        text_content: Optional[str] = None
    ) -> bool:
        """Envia un email usando SendGrid o SMTP (fallback)."""
        if text_content is None:
            text_content = self._html_to_text(html_content)
        
        if self.use_sendgrid:
            success = await self._send_via_sendgrid(to_email, subject, html_content, text_content)
            if success:
                logger.info(f"Email enviado a {to_email} via SendGrid")
                return True
            logger.warning("Fallo envio via SendGrid, intentando SMTP...")
        
        if self.use_smtp:
            success = await self._send_via_smtp(to_email, subject, html_content, text_content)
            if success:
                logger.info(f"Email enviado a {to_email} via SMTP")
                return True
        
        logger.warning(f"No se pudo enviar email a {to_email}. Mostrando en logs:")
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
        """Envia email usando SendGrid API."""
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
            logger.error(f"Error en SendGrid: {e}")
            return False
    
    async def _send_via_smtp(
        self,
        to_email: str,
        subject: str,
        html_content: str,
        text_content: str
    ) -> bool:
        """Envia email usando SMTP."""
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
            logger.error(f"Error en SMTP: {e}")
            return False
    
    def _html_to_text(self, html: str) -> str:
        """Convierte HTML a texto plano simple."""
        import re
        text = re.sub(r'<style[^>]*>.*?</style>', '', html, flags=re.DOTALL)
        text = re.sub(r'<[^>]+>', ' ', text)
        text = re.sub(r'\s+', ' ', text)
        return text.strip()
    
    # ============================================
    # EMAILS DE AUTENTICACION
    # ============================================
    
    async def send_otp_email(self, email: str, code: str) -> bool:
        """Envia codigo OTP para autenticacion de login."""
        subject = f"Tu codigo de verificacion QuickNote: {code}"
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Codigo de verificacion QuickNote</title>
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
            <p>Tu codigo de verificacion</p>
        </div>
        <div class="content">
            <p>Usa el siguiente codigo para completar tu autenticacion:</p>
            <div class="code-box">
                <span class="code">{code}</span>
            </div>
            <p>Este codigo expira en 10 minutos.</p>
            <p>Si no solicitaste este codigo, ignora este mensaje.</p>
        </div>
        <div class="footer">
            <p>QuickNote - Tu espacio de notas seguro</p>
        </div>
    </div>
</body>
</html>
"""
        
        text_content = f"""
Tu codigo de verificacion QuickNote es: {code}

Este codigo expira en 10 minutos.

Si no solicitaste este codigo, ignora este mensaje.

---
QuickNote - Tu espacio de notas seguro
"""
        
        return await self.send_email(email, subject, html_content, text_content)
    
    async def send_password_reset_otp(self, email: str, code: str) -> bool:
        """Envia codigo OTP para recuperacion de contrasena."""
        subject = "Recuperacion de contrasena - QuickNote"
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Recuperacion de contrasena - QuickNote</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #f4f4f4; padding: 20px; }}
        .container {{ max-width: 600px; margin: 0 auto; background: white; border-radius: 16px; overflow: hidden; }}
        .header {{ background: linear-gradient(135deg, #F59E0B 0%, #DC2626 100%); padding: 30px; text-align: center; }}
        .header h1 {{ color: white; margin: 0; }}
        .content {{ padding: 30px; text-align: center; }}
        .code-box {{ background: #f8f9fa; border: 2px dashed #F59E0B; border-radius: 12px; padding: 20px; margin: 20px 0; }}
        .code {{ font-size: 48px; font-weight: bold; color: #F59E0B; letter-spacing: 8px; }}
        .warning {{ color: #666; font-size: 14px; margin-top: 20px; }}
        .footer {{ background: #f8f9fa; padding: 20px; text-align: center; color: #999; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>QuickNote</h1>
            <p>Recuperacion de contrasena</p>
        </div>
        <div class="content">
            <p>Hemos recibido una solicitud para restablecer tu contrasena.</p>
            <p>Usa el siguiente codigo para continuar:</p>
            <div class="code-box">
                <span class="code">{code}</span>
            </div>
            <div class="warning">
                Este codigo expira en <strong>10 minutos</strong><br>
                Si no solicitaste este cambio, ignora este mensaje.
            </div>
        </div>
        <div class="footer">
            <p>QuickNote - Tu espacio de notas seguro</p>
        </div>
    </div>
</body>
</html>
"""
        
        text_content = f"""
Recuperacion de contrasena - QuickNote

Hemos recibido una solicitud para restablecer tu contrasena.

Tu codigo de verificacion es: {code}

Este codigo expira en 10 minutos.

Si no solicitaste este cambio, ignora este mensaje.

---
QuickNote - Tu espacio de notas seguro
"""
        
        return await self.send_email(email, subject, html_content, text_content)
    
    # ============================================
    # EMAILS DE SEGURIDAD
    # ============================================
    
    async def send_password_change_confirmation(self, email: str, name: str, ip_address: str = None) -> bool:
        """Envia confirmacion de cambio de contrasena."""
        subject = "Tu contrasena ha sido actualizada - QuickNote"
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Contrasena actualizada - QuickNote</title>
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
            <p>Confirmacion de cambio de contrasena</p>
        </div>
        <div class="content">
            <h2>Hola {name}!</h2>
            <p>Tu contrasena ha sido <strong>actualizada exitosamente</strong>.</p>
            
            <div class="info-box">
                <strong>Detalles del cambio:</strong><br>
                ? Fecha: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}<br>
                ? IP: {ip_address or 'No registrada'}
            </div>
            
            <p><strong>No realizaste este cambio?</strong><br>
            Si no fuiste tu quien cambio la contrasena, contacta inmediatamente a nuestro soporte.</p>
        </div>
        <div class="footer">
            <p>QuickNote - Tu espacio de notas seguro</p>
        </div>
    </div>
</body>
</html>
"""
        
        text_content = f"""
Hola {name},

Tu contrasena ha sido actualizada exitosamente.

Detalles del cambio:
- Fecha: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}
- IP: {ip_address or 'No registrada'}

No realizaste este cambio?
Si no fuiste tu, contacta inmediatamente a nuestro soporte.

---
QuickNote - Tu espacio de notas seguro
"""
        
        return await self.send_email(email, subject, html_content, text_content)
    
    async def send_password_expiry_warning(self, email: str, name: str, days_remaining: int) -> bool:
        """Envia advertencia de expiracion de contrasena."""
        subject = f"Tu contrasena expirara en {days_remaining} dias - QuickNote"
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Advertencia de expiracion - QuickNote</title>
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
            <p>Advertencia de expiracion</p>
        </div>
        <div class="content">
            <h2>Hola {name}!</h2>
            <p>Tu contrasena expirara en:</p>
            
            <div class="days">
                {days_remaining} dia{'' if days_remaining == 1 else 's'}
            </div>
            
            <p>Te recomendamos cambiar tu contrasena lo antes posible para mantener la seguridad de tu cuenta.</p>
        </div>
        <div class="footer">
            <p>QuickNote - Tu espacio de notas seguro</p>
        </div>
    </div>
</body>
</html>
"""
        
        text_content = f"""
Hola {name},

Tu contrasena expirara en {days_remaining} dia{'' if days_remaining == 1 else 's'}.

Te recomendamos cambiar tu contrasena lo antes posible para mantener la seguridad de tu cuenta.

---
QuickNote - Tu espacio de notas seguro
"""
        
        return await self.send_email(email, subject, html_content, text_content)
    
    async def send_security_alert(self, email: str, name: str, alert_type: str, details: Dict) -> bool:
        """Envia alerta de seguridad."""
        alert_titles = {
            "new_device": "Nuevo dispositivo detectado",
            "multiple_failures": "Multiples intentos fallidos de inicio de sesion",
            "password_changed": "Cambio de contrasena detectado",
            "suspicious_activity": "Actividad sospechosa detectada"
        }
        
        title = alert_titles.get(alert_type, "Alerta de seguridad")
        subject = f"Alerta de seguridad - QuickNote"
        
        details_text = ""
        for key, value in details.items():
            details_text += f"? {key}: {value}<br>"
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Alerta de seguridad - QuickNote</title>
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
            <p>Alerta de seguridad</p>
        </div>
        <div class="content">
            <h2>Hola {name}!</h2>
            <p>Hemos detectado la siguiente actividad en tu cuenta:</p>
            
            <div class="alert-box">
                <strong>{title}</strong><br>
                {details_text}
            </div>
            
            <p><strong>No reconoces esta actividad?</strong><br>
            Si no fuiste tu, recomendamos cambiar tu contrasena inmediatamente.</p>
        </div>
        <div class="footer">
            <p>QuickNote - Tu espacio de notas seguro</p>
        </div>
    </div>
</body>
</html>
"""
        
        text_content = f"""
Hola {name},

Alerta de seguridad: {title}

Detalles:
{self._format_details_text(details)}

No reconoces esta actividad?
Si no fuiste tu, te recomendamos cambiar tu contrasena inmediatamente.

---
QuickNote - Tu espacio de notas seguro
"""
        
        return await self.send_email(email, subject, html_content, text_content)
    
    def _format_details_text(self, details: Dict) -> str:
        """Formatea detalles para texto plano."""
        lines = []
        for key, value in details.items():
            lines.append(f"? {key}: {value}")
        return '\n'.join(lines)


# Funcion de conveniencia para mantener compatibilidad
async def send_otp_email(email: str, code: str) -> bool:
    """Funcion legacy para enviar OTP (mantiene compatibilidad)."""
    service = EmailService()
    return await service.send_otp_email(email, code)


# Instancia global
email_service = EmailService()