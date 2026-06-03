FROM python:3.12-slim

RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN pip install -e .

RUN useradd -m -s /bin/bash deepscout
USER deepscout

ENTRYPOINT ["deep-scout"]
CMD ["--help"]
