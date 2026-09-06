FROM python:3.12-slim

RUN addgroup --system boundsec && adduser --system --ingroup boundsec boundsec
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY boundsec/ ./boundsec/
COPY experiments/ ./experiments/
COPY tests/ ./tests/
COPY pyproject.toml README.md ./
RUN pip install --no-cache-dir -e . && mkdir -p results figures && chown -R boundsec /app

USER boundsec
ENTRYPOINT ["python", "-m", "boundsec.cli"]
CMD ["--help"]
