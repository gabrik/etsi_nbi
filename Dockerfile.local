FROM ubuntu:16.04

# Set the working directory to /app
WORKDIR /app/osm_nbi

# Copy the current directory contents into the container at /app
ADD . /app

RUN apt-get update && apt-get -y install git  python3 python3-jsonschema \
    python3-cherrypy3 python3-pymongo python3-yaml python3-pip \
    && pip3 install pip==9.0.3 \
    && pip3 install aiokafka \
    && mkdir -p /app/storage/kafka && mkdir -p /app/log 


EXPOSE 9999

LABEL Maintainer="alfonso.tiernosepulveda@telefonica.com" \
      Description="This implements a north bound interface for OSM" \
      Version="1.0" \
      Author="Alfonso Tierno"

# Used for local storage
VOLUME /app/storage
# Used for logs
VOLUME /app/log

# The following ENV can be added with "docker run -e xxx' to configure
# server
ENV OSMNBI_SOCKET_HOST     0.0.0.0
ENV OSMNBI_SOCKET_PORT     9999
# storage
ENV OSMNBI_STORAGE_PATH    /app/storage
# database
ENV OSMNBI_DATABASE_DRIVER mongo
ENV OSMNBI_DATABASE_HOST   mongo
ENV OSMNBI_DATABASE_PORT   27017
# web
ENV OSMNBI_STATIC_DIR      /app/osm_nbi/html_public
# logs
ENV OSMNBI_LOG_FILE        /app/log
ENV OSMNBI_LOG_LEVEL       DEBUG
# message
ENV OSMNBI_MESSAGE_DRIVER  kafka
ENV OSMNBI_MESSAGE_HOST    kafka
ENV OSMNBI_MESSAGE_PORT    9092

# Run app.py when the container launches
CMD ["python3", "nbi.py"]

