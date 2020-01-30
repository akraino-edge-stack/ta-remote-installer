#!/bin/bash
# Copyright 2019 Nokia
# Copyright 2020 ENEA
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

BASEIMAGE_TAG='centos:7.6.1810'

# For aarch64 use the closest available upstream version
if [ "$(uname -m)" = "aarch64" ]; then
    BASEIMAGE_TAG='centos@sha256:df89b0a0b42916b5b31b334fd52d3e396c226ad97dfe772848bdd6b00fb42bf0'
fi


help()
{
    echo -e "$(basename "$0") [-hs]"
    echo -e "   -h        display this help"
    echo -e "   -s        save image as tar to $TAR_IMAGE"
    echo
    echo -e "Proxy configuration is taken from environment variables"
    echo -e "http_proxy, https_proxy and no_proxy"
}

while getopts "hs" arg; do
    case $arg in
        h)
            help
            exit 0
            ;;
        s)
            SAVE_IMAGE="yes"
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
