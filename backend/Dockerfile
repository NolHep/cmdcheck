FROM python:3.12-slim

WORKDIR /app

RUN pip install uv

COPY pyproject.toml .
RUN uv pip install --system --no-cache ".[dev]"

COPY . .

# Fetch LOLBAS and GTFOBins data at build time.
# Submodules are not cloned by Railway's git fetch, so we pull them explicitly.
RUN apt-get update -qq && apt-get install -y -qq git \
    && git clone --depth=1 https://github.com/LOLBAS-Project/LOLBAS.git /tmp/lolbas \
    && rm -rf data/LOLBAS && mv /tmp/lolbas data/LOLBAS \
    && git clone --depth=1 https://github.com/GTFOBins/GTFOBins.github.io.git /tmp/gtfobins \
    && rm -rf data/GTFOBins && mv /tmp/gtfobins data/GTFOBins \
    && apt-get purge -y git && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
