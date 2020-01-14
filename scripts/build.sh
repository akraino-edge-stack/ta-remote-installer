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

cd "$(dirname "$0")"/..

TAR_IMAGE="remote-installer.tar"
DOCKERFILE='docker-build/remote-installer/Dockerfile'

help()
{
    echo -e "$(basename "$0") [-hs] -t <tag>"
    echo -e "   -h        display this help"
    echo -e "   -s        save image as tar to $TAR_IMAGE"
    echo -e "   -t <tag>  specify docker base image tag"
    echo
    echo -e "Proxy configuration is taken from environment variables"
    echo -e "http_proxy, https_proxy and no_proxy"
}

while getopts "hst:" arg; do
    case $arg in
        h)
            help
            exit 0
            ;;
        s)
            SAVE_IMAGE="yes"
            ;;
        t)
            BASEIMAGE_TAG="$OPTARG"
            ;;
  esac
done

docker build \
  --network=host \
  --no-cache \
  --force-rm \
  --build-arg BASEIMAGE_TAG="${BASEIMAGE_TAG}" \
  --build-arg HTTP_PROXY="${http_proxy}" \
  --build-arg HTTPS_PROXY="${https_proxy}" \
  --build-arg NO_PROXY="${no_proxy}" \
  --build-arg http_proxy="${http_proxy}" \
  --build-arg https_proxy="${https_proxy}" \
  --build-arg no_proxy="${no_proxy}" \
  --tag remote-installer \
  --file "${DOCKERFILE}" .


# could be compressed but it's only used until there is an registry
if [ -n "$SAVE_IMAGE" ]
then
    echo -e "Creating image tar ball at : $(dirname "$0")/$TAR_IMAGE"
    docker image save remote-installer >"$(dirname "$0")"/"$TAR_IMAGE"
fi
