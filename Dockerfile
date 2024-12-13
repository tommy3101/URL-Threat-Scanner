#Dockerfile
# FROM python:3.11.7-bookworm
# ENV PYTHONUNBUFFERED True
# ENV APP_HOME /back-end
# WORKDIR $APP_HOME
# COPY . ./

# RUN pip install --no-cache-dir --upgrade pip
# RUN pip install --no-cache-dir -r requirements.txt

# CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 0 app:app

# Allow statements and log messages to immediately appear in the logs
# Copy local code to the container image.
# Run the web service on container startup. Here we use the gunicorn
# webserver, with one worker process and 8 threads.
# For environments with multiple CPU cores, increase the number of workers
# to be equal to the cores available.
# Timeout is set to 0 to disable the timeouts of the workers to allow Cloud Run to handle instance scaling.

FROM python:3.11.7-bookworm
ENV PYTHONUNBUFFERED True
ENV APP_HOME /back-end
WORKDIR $APP_HOME
COPY . ./

RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 0 app:app
