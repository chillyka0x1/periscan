FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

EXPOSE 8000
ENV PORT=8000 ES_NO_BROWSER=1

# Im Container an alle Interfaces binden (Host-Port-Mapping via -p 8000:8000)
CMD ["python", "-c", "import os; from webapp import app; app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8000)))"]
