#!/bin/bash
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

set -e

cd "$(dirname "$0")"/..

API_PORT="15101"
BASE_DIR=""
CONT_NAME="remote-installer"
EXT_IP=""
HTTPS_PORT="443"
SSH_PORT="22222"
IMG_NAME="remote-installer"
ROOT_PW="root"

error()
{
    echo "ERROR : $1"
    [ -z $2 ] || help
    exit 1
}

help()
{
    echo -e "$(basename $0) [-h -a <api-port> -c <cont> -i <image> -r <pw> -s <https-port> ] -b <basedir> -e <ip-addr>"
    echo -e "   -h  display this help"
    echo -e "   -a  rest API port, default $API_PORT"
    echo -e "   -b  base directory, which contains images, certificates, etc."
    echo -e "   -c  container name, default $CONT_NAME"
    echo -e "   -d  use docker bridged networking, default host"
    echo -e "   -e  external ip address of  the docker"
    echo -e "   -i  image name, default $IMG_NAME"
    echo -e "   -l  login port for ssh, default $SSH_NAME"
    echo -e "   -p  root password, default $ROOT_PW"
    echo -e "   -s  secure https port, default $HTTPS_PORT"
}

while getopts "ha:b:de:l:s:c:p:i:" arg; do
    case $arg in
        h)
            help
            exit 0
            ;;
        b)
            BASE_DIR="$OPTARG"
            ;;
        e)
            EXT_IP="$OPTARG"
            ;;
        s)
            HTTPS_PORT="$OPTARG"
            ;;
        a)
            API_PORT="$OPTARG"
            ;;
        c)
            CONT_NAME="$OPTARG"
            ;;
        i)
            IMG_NAME="$OPTARG"
            ;;
        p)
            ROOT_PW="$OPTARG"
            ;;
        l)
            SSH_PORT="$OPTARG"
            ;;
        d)
            DOCKER_BRIDGE="YES"
            ;;
        *)
            error "Unknow argument!" showhelp
            ;;
  esac
done

[ -n "$EXT_IP" ] || error "No external IP defined!" showhelp
[ -n "$BASE_DIR" ] || error "No base directory defined!" showhelp

DOCKER_ENV="--env API_PORT=$API_PORT \
        --env HOST_ADDR=$EXT_IP \
        --env HTTPS_PORT=$HTTPS_PORT \
        --env PW=$ROOT_PW \
        --env SSH_PORT=$SSH_PORT "


if [ -n "$DOCKER_BRIDGE" ]
then
    echo -e "Start container with bridged networking..."
    cont_id="$(docker run --detach --rm --privileged \
        $DOCKER_ENV \
        --network=bridge \
        --volume "$BASE_DIR":/opt/remoteinstaller \
        --publish "$HTTPS_PORT":"$HTTPS_PORT" --publish 2049:2049 --publish "$API_PORT":"$API_PORT" \
        --name "$CONT_NAME" "$IMG_NAME")" \
        || error "failed to start container"
    echo -e "IP : $(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$cont_id")"

else
    echo -e "Start container with host networking..."
    cont_id="$(docker run --detach --rm --privileged \
        $DOCKER_ENV \
        --network=host \
        --volume "$BASE_DIR":/opt/remoteinstaller \
        --name "$CONT_NAME" "$IMG_NAME")" \
        || error "failed to start container"
fi
echo -e "Container successfully started"
echo -e "ID : $cont_id"
echo -e "Using ssh port : $SSH_PORT"
