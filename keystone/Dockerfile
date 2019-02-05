# Copyright 2018 Whitestack, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
# For those usages not covered by the Apache License, Version 2.0 please
# contact: esousa@whitestack.com or glavado@whitestack.com
##

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

# database
ENV DB_HOST                 keystone-db
ENV DB_PORT                 3306
ENV ROOT_DB_USER            root
ENV ROOT_DB_PASSWORD        admin
# keystone
ENV KEYSTONE_DB_PASSWORD    admin
ENV ADMIN_PASSWORD          admin
ENV NBI_PASSWORD            nbi

ENTRYPOINT ./start.sh
