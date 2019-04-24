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

CONT_NAME="remote-installer"

error()
{
    echo "ERROR : $1"
    [ -z $2 ] || help
    exit 1
}

help()
{
	echo -e "$(basename $0) [-h -a <api-port> -c <cont> ]"
	echo -e "   -h  display this help"
    echo -e "   -c  container name or ID, default $CONT_NAME"
}

while getopts "hc:" arg; do
    case $arg in
        h)
            help
            exit 0
            ;;
        c)
            CONT_NAME="$OPTARG"
            ;;
        *)
            error "Unknow argument!" showhelp
            ;;
  esac
done

docker container stop "$CONT_NAME" \
       || error "failed to stop container $CONT_NAME"

echo -e "Container successfully stopped : $CONT_NAME"

