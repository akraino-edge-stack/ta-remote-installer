#!/bin/bash

# Copyright 2019 Nokia

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

abort()
{
    echo "abort: $*"
    exit 1
}

syntax()
{
    cat <<EOF
./$0 [boot.iso] [output.iso] [configuration file]...
EOF
    abort "invalid command syntax"
}

ORGISO="$1"
OUTISO="$2"
shift 2
configs="$*"

test "$configs" || syntax "at least one config file must be provided" 
test -e "$ORGISO" || abort "Template .iso ($ORGISO) not found"

rm -f $OUTISO

cp $ORGISO $OUTISO
chmod 644 $OUTISO

echo Appending config.tgz
mkdir work.$$
cp $configs work.$$/
tar czvf - --owner 0 --group 0 -C work.$$ . | dd bs=64k conv=notrunc,sync oflag=append of=$OUTISO
rm -rf work.$$
