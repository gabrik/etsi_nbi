FROM ubuntu:16.04

LABEL Maintainer="esousa@whitestack.com" \
      Description="Openstack Keystone Instance" \
      Version="1.0" \
      Author="Eduardo Sousa"

EXPOSE 5000

WORKDIR /keystone

COPY scripts/start.sh /keystone/start.sh

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get autoremove -y && \
    apt-get install -y software-properties-common && \
    add-apt-repository -y cloud-archive:queens && \
    apt-get update && apt dist-upgrade -y && \
    apt-get install -y python-openstackclient keystone apache2 libapache2-mod-wsgi net-tools mysql-client && \
    rm -rf /var/lib/apt/lists/* && \
    chmod +x start.sh

ENV DB_HOST                 keystone-db     # DB Hostname
ENV DB_PORT                 3306            # DB Port
ENV ROOT_DB_USER            root            # DB Root User
ENV ROOT_DB_PASSWORD        admin           # DB Root Password
ENV KEYSTONE_DB_PASSWORD    admin           # Keystone user password
ENV ADMIN_PASSWORD          admin           # Admin password
ENV NBI_PASSWORD            nbi             # NBI password

ENTRYPOINT ./start.sh
