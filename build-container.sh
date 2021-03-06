#!/bin/bash
#
# Copyright (c) 2019 AT&T Intellectual Property. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

export DOCKER_REPO='nexus3.akraino.org:10003'
STAGING_BUILD=${STAGING_BUILD:=''}
AUTOSTAGING=${AUTOSTAGING:=''}

set -e -u -x -o pipefail

# In lieu of anything else, the build number will have to serve as the version
VERSION=0.0.$BUILD_NUMBER
if [ -n "$STAGING_BUILD" -a -n "$AUTOSTAGING" ]
then
    DOCKER_REPO='nexus3.akraino.org:10004'
fi

cd scripts/
./build.sh
docker tag remote-installer:latest ${DOCKER_REPO}/akraino/remote-installer:latest
docker tag remote-installer:latest ${DOCKER_REPO}/akraino/remote-installer:${VERSION}

docker images
docker push                        ${DOCKER_REPO}/akraino/remote-installer:latest
docker push                        ${DOCKER_REPO}/akraino/remote-installer:${VERSION}
