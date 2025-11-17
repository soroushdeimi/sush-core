FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH="/root/.local/bin:${PATH}"

WORKDIR /app

COPY requirements.txt ./requirements.txt
RUN python -m pip install --upgrade pip && \
    pip install --user -r requirements.txt

COPY . .
RUN pip install --user -e .

EXPOSE 8443 8080

CMD ["python", "examples/server_example.py", "--mode", "basic"]



