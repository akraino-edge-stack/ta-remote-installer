# Copyright 2019 Nokia
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM centos:7.6.1810
MAINTAINER Ralf Mueller <ralf.1.mueller@nokia.com>

ENV \
ETC_REMOTE_INST="/etc/remoteinstaller" \
SCRIPTS_DIR="/opt/scripts" \
PW="root" \
API_PORT="15101" \
API_LISTEN_ADDR="0.0.0.0" \
HTTPS_PORT="443" \
HOST_ADDR="127.0.0.1" \
STARTUP="/etc/remoteinstaller/startup.sh" \
CA_CERT="cacert.pem" \
CLIENT_CERT="clientcert.pem" \
CLIENT_KEY="clientkey.pem" \
SERVER_CERT="servercert.pem" \
SERVER_KEY="serverkey.pem" \
INSTALLER_MOUNT="/opt/remoteinstaller" \
SSH_PORT="22"

ENV IMAGES_STORE="$INSTALLER_MOUNT/images"
ENV IMAGES_HTML="/var/www/lighttpd/images"

RUN mkdir -p "$INSTALLER_MOUNT"

# prepare for basic systemd services
RUN yum -y install systemd epel-release; yum clean all \
&& (cd /lib/systemd/system/sysinit.target.wants/; for i in *; do [ $i == systemd-tmpfiles-setup.service ] || rm -f $i; done) \
&& rm -f /lib/systemd/system/multi-user.target.wants/* \
&& rm -f /etc/systemd/system/*.wants/* \
&& rm -f /lib/systemd/system/local-fs.target.wants/* \
&& rm -f /lib/systemd/system/sockets.target.wants/*udev* \
&& rm -f /lib/systemd/system/sockets.target.wants/*initctl* \
&& rm -f /lib/systemd/system/basic.target.wants/* \
&& rm -f /lib/systemd/system/anaconda.target.wants/* \
\
# Services for the workload \
&& yum install -y iproute wget openssh-server lighttpd nfs-utils \
python-setuptools python2-eventlet python-routes PyYAML \
python-netaddr pexpect net-tools tcpdump \
ipmitool openssh-clients sshpass nmap-ncat python-configparser\
# mod_ssl \
&& systemctl enable sshd \
&& systemctl enable lighttpd \
&& systemctl enable nfs-server \
&& echo "$IMAGES_STORE" "*(rw,sync,no_root_squash,no_all_squash)" >>/etc/exports


# lighthttpd configuration

RUN sed -i 's/server.use-ipv6 = "enable"/server.use-ipv6 = "disable"/' /etc/lighttpd/lighttpd.conf \
&& echo $'\n\
# SSL configuration\n\
ssl.engine = "enable"\n\
ssl.privkey = "/opt/remoteinstaller/certificates/serverkey.pem"\n\
ssl.pemfile = "/opt/remoteinstaller/certificates/servercert.pem"\n\
ssl.ca-file = "/opt/remoteinstaller/certificates/cacert.pem"\n\
ssl.verifyclient.activate = "enable"\n\
ssl.verifyclient.enforce = "enable"\n\
' >> /etc/lighttpd/lighttpd.conf \
&& mkdir -p "$IMAGES_HTML"


# Install hw-detector from LF
RUN wget -O x.tgz 'https://gerrit.akraino.org/r/gitweb?p=ta/hw-detector.git;a=snapshot;h=HEAD;sf=tgz' \
&& tar -xzf x.tgz \
&& rm -f x.tgz \
&& pushd hw-detector*/src \
&& python setup.py install \
&& popd \
&& rm -rf hw-detector*


# Install remote-installer to image
COPY src "$INSTALLER_MOUNT"
RUN pushd "$INSTALLER_MOUNT" \
&& python setup.py install \
&& rm -rf * \
&& popd

RUN mkdir -p "$SCRIPTS_DIR" \
&& mkdir -p "$ETC_REMOTE_INST"

COPY src/scripts/get_journals.sh "$SCRIPTS_DIR"/

RUN echo '#!/bin/bash -x' >>$STARTUP \
&& echo "function handle_sigterm() {" >>$STARTUP \
&& echo -e "  echo Stopping nfs-server" >>$STARTUP \
&& echo -e "  systemctl stop nfs-server" >>$STARTUP \
&& echo -e "  exit 0" >>$STARTUP \
&& echo "}" >>$STARTUP \
&& echo "trap 'handle_sigterm' 15" >>$STARTUP \
&& echo 'printenv >/etc/remoteinstaller/environment' >>$STARTUP \
&& echo 'mkdir /run/systemd/system' >>$STARTUP \
&& echo 'nohup /usr/lib/systemd/systemd --system' '&>/dev/null &' >>$STARTUP \
&& echo "echo -e \"\$PW\n\$PW\n\n\" |passwd" >>$STARTUP \
&& echo mount -o bind "$IMAGES_STORE" "$IMAGES_HTML" >>$STARTUP \
&& echo 'sed -i "s/server.port = 80/server.port = $HTTPS_PORT/" /etc/lighttpd/lighttpd.conf' >>$STARTUP \
&& echo 'sed -i "s/.*Port 22/Port $SSH_PORT/" /etc/ssh/sshd_config' >>$STARTUP \
# && echo "echo \\\$SERVER[\\\"sockets\\\"] == \\\"0.0.0.0:\$HTTPS_PORT {}\\\" >> /etc/lighttpd/lighttpd.conf" >>$STARTUP \
&& echo python /lib/python2.7/site-packages/remoteinstaller-1.0-py2.7.egg/remoteinstaller/server/server.py \
   -H \$API_LISTEN_ADDR -P \$API_PORT -S \$HOST_ADDR -T \$HTTPS_PORT \
   -C \$SERVER_CERT -K \$SERVER_KEY -c \$CLIENT_CERT -k \$CLIENT_KEY -A \$CA_CERT -d \& \
   >>$STARTUP \
&& echo 'while [ false ]; do sleep 5 ;done' >>$STARTUP  \
&& chmod +x $STARTUP

ENTRYPOINT ["/etc/remoteinstaller/startup.sh"]

#  CMD [ "arg1" ]

