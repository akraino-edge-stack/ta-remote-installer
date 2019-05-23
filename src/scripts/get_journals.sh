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

hosts_names_file="$1"
for host in $(cat ${hosts_names_file}); do
    if [ "${host}" != "$(hostname)" ]; then
        address=${host}
        if [ -e /etc/infra_internal_addresses ]; then
            internal_ip=$(grep ${host} /etc/infra_internal_addresses | cut -d ' ' -f 2)
            if [ -n "$internal_ip" ]; then
                address=${internal_ip}
            fi
        fi
        ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ServerAliveInterval=60 ${address} "sudo journalctl" > /tmp/journal_${host}.log
        ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ServerAliveInterval=60 ${address} "sudo journalctl -o json" > /tmp/journal_${host}_json.log
    else
        sudo journalctl > /tmp/journal_${host}.log
        sudo journalctl -o json > /tmp/journal_${host}_json.log
    fi
done

cd /tmp
tar czf node_journals.tgz journal_*.log
rm -f journal_*.log
cd -
