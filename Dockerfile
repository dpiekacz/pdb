# Set the base image
FROM python:3.8.2-alpine

# Dockerfile author / maintainer
MAINTAINER Daniel Piekacz <daniel@piekacz.net>

# This hack is widely applied to avoid python printing issues in docker containers.
# See: https://github.com/Docker-Hub-frolvlad/docker-alpine-python3/pull/13
ENV PYTHONUNBUFFERED=1

# Updating apt list of packages and upgrading currently installed
RUN apk -U update
RUN apk -U upgrade

# Installing Redis
RUN apk -U add supervisor
RUN apk -U add redis

# Install Python dependencies
COPY requirements.txt /
RUN pip install --upgrade pip
RUN pip install -r /requirements.txt

RUN sed -i "s/from client import PeeringDB  # noqa/from peeringdb.client import PeeringDB/g" /usr/local/lib/python3.8/site-packages/peeringdb/__init__.py

# Copy the app
COPY . /app
WORKDIR /app

# Setup Supervisord
RUN mkdir -p /etc/supervisord.d

# general config for supervisord
RUN echo  $'[supervisord] \n\
user=root \n\
[unix_http_server] \n\
file = /tmp/supervisor.sock \n\
chmod = 0777 \n\
chown= nobody:nogroup \n\
[supervisord] \n\
logfile = /tmp/supervisord.log \n\
logfile_maxbytes = 50MB \n\
logfile_backups=10 \n\
loglevel = info \n\
pidfile = /tmp/supervisord.pid \n\
nodaemon = true \n\
umask = 022 \n\
identifier = supervisor \n\
[supervisorctl] \n\
serverurl = unix:///tmp/supervisor.sock \n\
[rpcinterface:supervisor] \n\
supervisor.rpcinterface_factory = supervisor.rpcinterface:make_main_rpcinterface \n\
[include] \n\
files = /etc/supervisord.d/*.conf' >> /etc/supervisord.conf

# starting redis-server using supervisord
RUN echo $'[supervisord] \n\
nodaemon=true \n\
[program:redis] \n\
command=redis-server /etc/redis.conf \n\
autostart=true \n\
autorestart=true \n\
stdout_logfile=/var/log/redis/stdout.log \n\
stdout_logfile_maxbytes=0MB \n\ 
stderr_logfile=/var/log/redis/stderr.log \n\
stderr_logfile_maxbytes=10MB \n\
exitcodes=0 ' >> /etc/supervisord.d/redis.conf

# starting the python app
RUN echo $'[supervisord] \n\
nodaemon=true \n\
[program:python-app] \n\
command=python ./pdb_report.py\n\
autorestart=unexpected \n\
stdout_logfile=/dev/fd/1 \n\
stdout_logfile_maxbytes=0MB \n\
stderr_logfile=/dev/fd/2 \n\
stderr_logfile_maxbytes=0MB \n\
#redirect_stderr=true \n\
exitcodes=0 ' >> /etc/supervisord.d/python-app.conf

# ENTRYPOINT ["./pdb_report.py"]
ENTRYPOINT ["supervisord", "--nodaemon", "--configuration", "/etc/supervisord.conf"]

EXPOSE 5000
