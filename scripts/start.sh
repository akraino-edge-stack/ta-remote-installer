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
    echo -e "   -c  container name, default $CONT_NAME"
	echo -e "   -b  base directory, which contains images, certificates, etc."
	echo -e "   -e  external ip address of the docker"
	echo -e "   -i  secure https port, default $IMG_NAME"
	echo -e "   -p  root password, default $ROOT_PW"
	echo -e "   -s  secure https port, default $HTTPS_PORT"
}

while getopts "ha:b:e:s:c:p:i:" arg; do
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
        *)
            error "Unknow argument!" showhelp
            ;;
  esac
done

[ -n "$EXT_IP" ] || error "No external IP defined!" showhelp
[ -n "$BASE_DIR" ] || error "No base directory defined!" showhelp

cont_id="$(docker run --detach --rm --privileged \
     --env API_PORT="$API_PORT" \
     --env HOST_ADDR="$EXT_IP" \
     --env HTTPS_PORT="$HTTPS_PORT" \
     --env PW="$ROOT_PW" \
     --volume "$BASE_DIR":/opt/remoteinstaller --publish "$HTTPS_PORT":"$HTTPS_PORT" -p 2049:2049 -p "$API_PORT":"$API_PORT" --name "$CONT_NAME" "$IMG_NAME")" \
       || error "failed to start container"

echo -e "Container successfully started"
echo -e "ID : $cont_id"
echo -e "IP : $(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$cont_id")"
