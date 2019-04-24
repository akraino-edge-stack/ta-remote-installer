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

from .or18 import OR18
import logging

class BMCException(Exception):
    pass

class OE19(OR18):
    def __init__(self, host, user, passwd, log_path=None):
        super(OE19, self).__init__(host, user, passwd, log_path)

    def _set_boot_from_virtual_media(self):
        logging.debug('Set boot from floppy (%s), and boot after that', self._host)
        self._run_ipmitool_command('chassis bootdev floppy options=persistent')
