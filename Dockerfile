FROM python:3.10-alpine

WORKDIR /app

COPY . .

EXPOSE 3000

RUN apk update && apk --no-cache add openssl bash curl &&\
    chmod +x runew.py &&\
    pip install -r requirements.txt
    
CMD ["python3", "runew.py"]
