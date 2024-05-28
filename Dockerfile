FROM python:3.12.3

WORKDIR /vexgen

COPY app/ /vexgen/app/
COPY requirements.txt /vexgen/
COPY .env /vexgen/

RUN pip install --upgrade pip

RUN pip install -r requirements.txt

EXPOSE 8000

CMD uvicorn app.main:app --host 0.0.0.0 --port 8000
