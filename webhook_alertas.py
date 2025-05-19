#Token de seguridad
import os
from flask import Flask, request, jsonify
import logging
import sqlite3
from datetime import datetime
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import hashlib

logging.basicConfig(
    filename="webhook_alertas.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

conn = sqlite3.connect("alertas.db", check_same_thread=False)
conn.execute("""
CREATE TABLE IF NOT EXISTS alertas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fecha TEXT,
    contenido TEXT
)
""")
conn.commit()

app = Flask(__name__)
#Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["10 per minute"]  # Limita a 10 requests por minuto por IP
)

SECRET_TOKEN = os.environ.get("WEBHOOK_TOKEN") #Setear antes de ejecutar
if not SECRET_TOKEN:
    raise ValueError("WEBHOOK_TOKEN no está definido en el entorno")

@app.route('/alerta', methods=['POST'])
def recibir_alerta():
    if request.content_length and request.content_length > 10_000:
        logging.warning(f"Payload demasiado grande: {request.content_length} bytes")
        return jsonify({"status": "error", "message": "Payload demasiado grande"}), 413

    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer ") or auth.split()[1] != SECRET_TOKEN:
        ip = request.remote_addr
        logging.warning(f"Token inválido desde IP: {ip}")
        return jsonify({"status": "error", "message": "Token inválido"}), 401

    data = request.get_json(force=True)

    if not isinstance(data.get("alertas"), list):
        logging.warning("Formato inválido: 'alertas' no es lista.")
        return jsonify({"status": "error", "message": "Formato de alerta inválido"}), 400

    print("ALERTA RECIBIDA:")

    for alerta in data.get('alertas', []):
        print(alerta)
    for linea in alerta.splitlines():
        logging.info(linea)
    conn.execute("INSERT INTO alertas (fecha, contenido) VALUES (?, ?)",
                 (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), alerta))
    conn.commit()

    hash_final = hashlib.sha256("\n".join(data["alertas"]).encode()).hexdigest()
    return jsonify({"status": "recibido", "hash": hash_final}), 200 #Hash para validacion de integridad

if __name__ == "__main__":
    app.run(port=5000)


