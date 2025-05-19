# CH2

Este proyecto simula una aplicación de seguridad que analiza correos electrónicos (formato `.json`) y detecta posibles datos sensibles o peligrosos. Se aplica una arquitectura con varias capas de protección y validaciones, tanto en el cliente como en el servidor receptor (webhook).

---

### Características implementadas

#### Cliente (`analizador_correos.py`)
- Análisis de correos reales desde archivos `.json`
- Detección de palabras sensibles tipo DLP (`confidencial`, `contraseña`)
- Filtro CASB por dominios seguros (`@empresa.com`, `@google.com`)
- Análisis de adjuntos peligrosos por extensión y MIME
- Regex para detectar posibles credenciales duras
- Generación de archivo `alertas.txt` con las detecciones
- Cifrado GPG del archivo (`alertas.txt.gpg`) con clave pública
- Firma digital separada (`alertas.txt.sig`) con clave privada
- Eliminación segura del archivo de texto original
- Envío de las alertas por webhook HTTP con token Bearer
- Verificación de disponibilidad del webhook antes de enviar
- Validación de integridad comparando hash local con hash remoto
- Logging estructurado a archivo `log_analisis.log`
- Hash SHA-256 del reporte completo

#### Webhook (`webhook_alertas.py`)
- Verificación del token Bearer
- Límite de tamaño del payload (10 KB) — protección DoS
- Validación estructural del JSON (`alertas[]`)
- Logging estructurado a `webhook_alertas.log`
- Registro de la IP en intentos de acceso no autorizados
- Persistencia de alertas en SQLite (`alertas.db`)
- Respuesta con hash SHA-256 del contenido recibido

---

### Requisitos

- Python 3.11+
- GPG (GNU Privacy Guard)
- Flask
- Flask-Limiter (opcional pero recomendado)

```bash
pip install flask flask-limiter requests
```

---

### Cómo ejecutar

1. **Generar claves GPG:**
```bash
gpg --full-generate-key
```

2. **Exportar la clave pública del destinatario:**
```bash
gpg --armor --export alias@alias.com > public.key
```

3. **Configurar variables de entorno:**
En PowerShell o terminal:

```bash
$env:WEBHOOK_TOKEN = "As3ReJ3@[ha/"
$env:GPG_RECIPIENT = "alias@alias.com"
$env:GPG_SIGNER = "alias@alias.com"
```

4. **Levantar el servidor:**
```bash
python webhook_alertas.py
```

5. **Ejecutar el analizador:**
```bash
python analizador_correos.py
```

---
