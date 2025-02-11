FROM python:3.10-slim

WORKDIR /usr/src/app
COPY . .
RUN apt-get update && apt-get install -y python3-tk && pip install --no-cache-dir gradio gradio_toggle
EXPOSE 7860
ENV GRADIO_SERVER_NAME="0.0.0.0"

CMD ["python", "app.py"]