import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
from app.config import settings

logger = logging.getLogger(__name__)

async def send_otp_email(email: str, code: str):
    """Envía un email con el código OTP"""
    try:
        logger.info(f"📧 Iniciando envío de OTP a {email}...")
        logger.info(f"📧 Código: {code}")
        
        # Verificar si hay configuración SMTP
        if not settings.smtp_user or not settings.smtp_password:
            logger.warning("⚠️  SMTP no configurado. Mostrando código en logs:")
            logger.info(f"📧 [DEV] ========================================")
            logger.info(f"📧 [DEV] Para: {email}")
            logger.info(f"📧 [DEV] Código OTP: {code}")
            logger.info(f"📧 [DEV] ========================================")
            return True
        
        # Crear el mensaje
        msg = MIMEMultipart('alternative')
        msg["From"] = f"{settings.smtp_from_name} <{settings.smtp_from}>"
        msg["To"] = email
        msg["Subject"] = f"🔐 Tu código de verificación QuickNote: {code}"
        
        # HTML del email
        html = f"""
        <!DOCTYPE html>
        <html>
        <head><meta charset="UTF-8"></head>
        <body style="font-family: Arial, sans-serif; background: #f4f4f4; padding: 20px;">
            <div style="max-width: 600px; margin: 0 auto; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center;">
                    <h1 style="color: white; margin: 0;">🔐 QuickNote</h1>
                    <p style="color: #e0e0ff; margin: 10px 0 0;">Tu código de verificación</p>
                </div>
                <div style="padding: 30px; text-align: center;">
                    <p style="font-size: 16px; color: #333; margin-bottom: 20px;">
                        Usa el siguiente código para iniciar sesión:
                    </p>
                    <div style="background: #f8f9fa; border: 2px dashed #667eea; border-radius: 10px; padding: 20px; margin: 20px 0;">
                        <span style="font-size: 48px; font-weight: bold; color: #667eea; letter-spacing: 10px;">
                            {code}
                        </span>
                    </div>
                    <p style="color: #666; font-size: 14px;">
                        ⏰ Expira en 10 minutos<br>
                        🔒 Si no solicitaste este código, ignora este mensaje.
                    </p>
                </div>
            </div>
        </body>
        </html>
        """
        
        text = f"Tu código de verificación QuickNote es: {code}\n\nExpira en 10 minutos."
        
        msg.attach(MIMEText(text, 'plain', 'utf-8'))
        msg.attach(MIMEText(html, 'html', 'utf-8'))
        
        # Conectar al servidor SMTP
        logger.info(f"📡 Conectando a {settings.smtp_host}:{settings.smtp_port}...")
        
        if settings.smtp_port == 465:
            server = smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=10)
        else:
            server = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10)
            server.starttls()
        
        logger.info("✅ Conexión establecida")
        
        # Login
        logger.info(f"🔑 Iniciando sesión como {settings.smtp_user}...")
        server.login(settings.smtp_user, settings.smtp_password)
        logger.info("✅ Login exitoso")
        
        # Enviar
        logger.info(f"📤 Enviando email a {email}...")
        server.send_message(msg)
        logger.info(f"✅ Email enviado exitosamente a {email}")
        
        server.quit()
        return True
        
    except smtplib.SMTPAuthenticationError as e:
        logger.error(f"❌ Error de autenticación SMTP: {e}")
        logger.error("   💡 Verifica que la contraseña de aplicación sea correcta")
        logger.error("   💡 Asegúrate de tener activada la verificación en dos pasos")
        return False
    except smtplib.SMTPException as e:
        logger.error(f"❌ Error SMTP: {e}")
        return False
    except Exception as e:
        logger.error(f"❌ Error inesperado: {type(e).__name__}: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False