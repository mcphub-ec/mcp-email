FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Expose the default MCP port; actual port via MCP_PORT at runtime
EXPOSE 8000

# Healthcheck: connect to the TCP port indicated by MCP_PORT env (default 8000).
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import socket, os; s=socket.create_connection(('localhost', int(os.getenv('MCP_PORT', '8000'))), 5); s.close()" || exit 1

CMD ["python", "server.py"]
