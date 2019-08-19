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

import subprocess
import time
import logging
import ipaddress
import pexpect

from ..bmctools import BMC

class NokiaHW(BMC):
    def _wait_for_bmc_nfs_service(self, timeout, expected_status):
        logging.debug('Wait for BMC NFS service')

        start_time = int(time.time()*1000)

        status = ''
        while status != expected_status:
            status = self._get_bmc_nfs_service_status()

            if status == expected_status or status == 'nfserror':
                logging.debug('Breaking from wait loop. status = %s', status)
                break

            time_now = int(time.time()*1000)
            if time_now-start_time > timeout*1000:
                logging.debug('Wait timed out')
                break
            time.sleep(10)

        return status == expected_status

    def _get_bmc_nfs_service_status(self):
        raise NotImplementedError
