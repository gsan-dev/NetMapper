# Build context: raíz del repo (necesita common/ y analysis/ además de discovery/)
#
# El pipeline necesita permisos elevados para ARP scanning y captura
# pasiva (Scapy). En docker-compose.yml se le da network_mode: host y
# cap_add: NET_ADMIN, NET_RAW (ver comentarios allí) — network_mode: host
# es imprescindible además para que vea el tráfico/hosts reales de tu
# red en vez de la red interna del contenedor.
FROM python:3.11-slim

WORKDIR /app

COPY common/ common/
COPY analysis/ analysis/
COPY discovery/ discovery/

RUN pip install --no-cache-dir \
    -r analysis/requirements.txt \
    -r discovery/requirements.txt

WORKDIR /app/discovery

CMD ["python", "main.py", "--continuous"]
