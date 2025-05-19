# utf-8

import os
import glob
import json
import subprocess
import requests
import logging
import mimetypes
import hashlib
import re

# Logging estructurado
logging.basicConfig(
    filename="log_analisis.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# Parámetros
palabras_sensibles = ["confidencial", "contraseña"]
dominios_confiables = ["empresa.com", "google.com"]
extensiones_peligrosas = [".zip", ".exe", ".bat", ".js"]
archivo_alertas = "alertas.txt"
archivo_alertas_cifrado = "alertas.txt.gpg"
archivo_firma = "alertas.txt.sig"
gpg_recipient = os.environ.get("GPG_RECIPIENT", "alias@alias.com")
gpg_signer = os.environ.get("GPG_SIGNER", "alias@alias.com")

# Análisis real
alertas_generadas = []

for fichero in glob.glob("*.json"):
    print(f"Analizando archivo: {fichero}")
    try:
        with open(fichero, "r", encoding="utf-8") as f:
            correo = json.load(f)
    except Exception as e:
        print(f"Error leyendo {fichero}: {e}")
        continue

    remitente = correo.get("from", "").lower()
    asunto = correo.get("subject", "").lower()
    cuerpo = correo.get("body", "").lower()
    adjuntos = correo.get("attachments", [])

    dominio_remitente = remitente.split("@")[-1] if "@" in remitente else ""
    if any(dominio_remitente.endswith(dom) for dom in dominios_confiables):
        continue

    hallazgos = []

    # Detectar palabras sensibles
    for palabra in palabras_sensibles:
        if palabra in asunto or palabra in cuerpo:
            hallazgos.append(f"Palabra sensible detectada: '{palabra}'")

    # Regex de posibles credenciales
    if re.search(r"(usuario|user|login|clave|password)\s*[:=]\s*\S+", cuerpo, re.IGNORECASE):
        hallazgos.append("Posible cadena de credenciales detectada en el cuerpo del correo")

    # Adjuntos peligrosos
    for adj in adjuntos:
        nombre_adj = adj.lower()
        tipo_mime, _ = mimetypes.guess_type(nombre_adj)
        for ext in extensiones_peligrosas:
            if nombre_adj.endswith(ext) or (tipo_mime and any(e in tipo_mime for e in ['zip', 'x-javascript', 'x-msdownload'])):
                hallazgos.append(f"Adjunto potencialmente peligroso: '{adj}'")
                break

    if hallazgos:
        info_alerta = (
            f"Archivo: {fichero}\n"
            f"Remitente: {remitente}\n"
            f"Asunto: {correo.get('subject', '')}\n"
            f"Hallazgos:\n"
        )
        for h in hallazgos:
            info_alerta += f"    * {h}\n"
        alertas_generadas.append(info_alerta)

# Si hay alertas...
if alertas_generadas:
    try:
        with open(archivo_alertas, "w", encoding="utf-8") as f:
            f.write("ALERTAS DE SEGURIDAD:\n")
            f.write("=====================\n\n")
            for alerta in alertas_generadas:
                f.write(alerta + "\n")
    except Exception as e:
        print(f"Error escribiendo archivo de alertas: {e}")

    #Cifrado
    try:
        subprocess.run([
            "gpg", "--batch", "--yes",
            "--output", archivo_alertas_cifrado,
            "--encrypt", "--recipient", gpg_recipient,
            archivo_alertas
        ], check=True)
        print(f"Archivo cifrado como {archivo_alertas_cifrado}")
    except subprocess.CalledProcessError as e:
        print(f"Error cifrando archivo: {e}")

    #Firma
    try:
        subprocess.run([
            "gpg", "--batch", "--yes",
            "--output", archivo_firma,
            "--detach-sign", "--local-user", gpg_signer,
            archivo_alertas
        ], check=True)
        print(f"🖋️ Archivo firmado como {archivo_firma}")
        if os.path.exists(archivo_alertas_cifrado) and os.path.exists(archivo_firma):
            os.remove(archivo_alertas)
            print("🧹 Archivo alertas.txt eliminado tras cifrado y firma")
    except subprocess.CalledProcessError as e:
        print(f"Error firmando archivo: {e}")

    #Envío al webhook
    try:
        token = os.environ.get("WEBHOOK_TOKEN")
        if not token:
            print("No se encontró WEBHOOK_TOKEN.")
            exit(1)

        headers = {"Authorization": f"Bearer {token}"}

        try:
            test = requests.get("http://localhost:5000", timeout=2)
        except requests.exceptions.RequestException:
            print("Webhook no disponible.")
            exit(1)

        data = {"alertas": alertas_generadas}
        resp = requests.post("http://localhost:5000/alerta", json=data, headers=headers)
        print(f"Webhook respondió: {resp.status_code}")

        if resp.status_code == 200:
            hash_local = hashlib.sha256("\n".join(alertas_generadas).encode()).hexdigest()
            hash_remoto = resp.json().get("hash")
            if hash_local == hash_remoto:
                print("Integridad verificada: hashes coinciden.")
            else:
                print("¡Hash mismatch! Posible alteración en tránsito.")

        if resp.status_code != 200:
            logging.warning(f"Webhook devolvió código {resp.status_code}: {resp.text}")

    except Exception as e:
        print(f"Error al enviar datos al webhook: {e}")

    #Generar hash del reporte
    try:
        hash_total = hashlib.sha256("\n".join(alertas_generadas).encode()).hexdigest()
        logging.info(f"Hash SHA-256 del reporte: {hash_total}")
    except Exception as e:
        logging.warning(f"Error generando hash: {e}")

else:
    print("No se generaron alertas. Ningún correo sospechoso encontrado.")
