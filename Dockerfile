FROM python:3.14-slim

WORKDIR /usr/src/app
COPY . .
RUN pip install --no-cache-dir gradio pandas
EXPOSE 7860
ENV GRADIO_SERVER_NAME="0.0.0.0"
CMD ["python", "app.py"]
