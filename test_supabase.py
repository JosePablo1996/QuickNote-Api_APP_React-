from app.services.supabase_client import supabase_client
from app.config import settings

print(f"URL: {settings.supabase_url}")
print(f"Key: {settings.supabase_key[:20]}...")

try:
    # Probar conexión haciendo una consulta simple
    result = supabase_client.table("notes").select("*").limit(1).execute()
    print("✅ Conexión exitosa a Supabase")
    print(f"Datos: {result.data}")
except Exception as e:
    print(f"❌ Error: {e}")