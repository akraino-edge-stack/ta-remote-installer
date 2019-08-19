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

import logging
import time
import json
import requests

from ..bmctools import BMC
from ..bmctools import BMCException

'''
    Implemented based on examples from:
    https://github.com/dell/iDRAC-Redfish-Scripting/blob/master/Redfish%20Python/InsertEjectVirtualMediaREDFISH.py
    https://github.com/dell/iDRAC-Redfish-Scripting/blob/master/Redfish%20Python/SetNextOneTimeBootVirtualMediaDeviceOemREDFISH.py
'''
class DELL(BMC):
    IDRAC_CD_PATH = '/redfish/v1/Managers/iDRAC.Embedded.1/VirtualMedia/CD'
    IDRAC_INSERT_MEDIA_PATH = 'Actions/VirtualMedia.InsertMedia'
    IDRAC_EJECT_MEDIA_PATH = 'Actions/VirtualMedia.EjectMedia'
    IDRAC_IMPORT_SYSTEM_CONFIGURATION = '/redfish/v1/Managers/iDRAC.Embedded.1/Actions/Oem/EID_674_Manager.ImportSystemConfiguration'
    IDRAC_IMPORT_ONETIMEBOOT_VCD_DVD_PAYLOAD = {"ShareParameters":{"Target":"ALL"},"ImportBuffer":"<SystemConfiguration><Component FQDD=\"iDRAC.Embedded.1\"><Attribute Name=\"ServerBoot.1#BootOnce\">Enabled</Attribute><Attribute Name=\"ServerBoot.1#FirstBootDevice\">VCD-DVD</Attribute></Component></SystemConfiguration>"}

    def attach_virtual_cd(self, media_info):
        logging.info('attach_virtual_cd called')

        if self._verify_media_inserted():
            self._detach_virtual_media()

        self._check_supported_idrac_version()

        #image_uri = 'https://{}{}/{}'.format(media_info['server'], media_info['path'], media_info['image'])
        if media_info.get('insecure_boot_image', False):
            image_uri_protocol = 'http'
        else:
            image_uri_protocol = 'https'
        image_uri = '{}://testremoteinstaller.cloud.nsn-rdnet.net/{}'.format(image_uri_protocol, media_info['image'])

        data = {'Image': image_uri, 'Inserted':True, 'WriteProtected':True}

        self._post('{}/{}'.format(DELL.IDRAC_CD_PATH, DELL.IDRAC_INSERT_MEDIA_PATH), data)

        self._wait_media_inserted()

    def _set_boot_from_virtual_media(self):
        logging.debug('_set_boot_from_virtual_media called')

        #status_code = self._run_ipmitool_raw_command('0x00 0x08 0x05 0xc0 0x20 0x00 0x00 0x00')
        #if status_code[0] != '':
        #    raise BMCException('Could not set boot from virtual media (rc={})'.format(status_code[0]))

        response = self._post(DELL.IDRAC_IMPORT_SYSTEM_CONFIGURATION, DELL.IDRAC_IMPORT_ONETIMEBOOT_VCD_DVD_PAYLOAD)

        task_id = response.headers['Location']
        self._wait_for_task_completed(task_id)

        self._verify_task_ok(task_id)

    def _detach_virtual_media(self):
        logging.debug('_detach_virtual_media called')

        if not self._verify_media_inserted():
            logging.debug('Media already detached')
            return

        self._check_supported_idrac_version()

        data = {}

        self._post('{}/{}'.format(DELL.IDRAC_CD_PATH, DELL.IDRAC_EJECT_MEDIA_PATH), data)

        self._wait_media_ejected()

    def _get(self, path):
        logging.debug('_get called for %s', path)

        response = requests.get('https://{}{}'.format(self.get_host(), path), verify=False, auth=(self.get_user(), self.get_passwd()))
        if response.status_code > 299:
            logging.debug('GET request failed: %s (%s)', response.text, response.status_code)
            raise BMCException('Could not get data from BMC ({}, {})'.format(self.get_host(), path))

        return response.json()

    def _post(self, path, data):
        logging.debug('_post called for %s with %s', path, data)
        headers = {'content-type': 'application/json'}
        response = requests.post('https://{}{}'.format(self.get_host(), path), data=json.dumps(data), headers=headers, verify=False, auth=(self.get_user(), self.get_passwd()))

        if response.status_code > 299:
            logging.debug('POST request failed: %s (%s)', response.text, response.status_code)
            raise BMCException('Could not post data to BMC ({}, {}, {})'.format(self.get_host(), path, data))

        return response

    def _wait_for_task_completed(self, task_id, timeout=60):
        logging.debug('_wait_for_task_completed called for %s (timeout=%s)', task_id, timeout)

        if not self._wait_status(timeout, self._verify_task_completed, args=(task_id,)):
            raise BMCException('Task did not complete')

    def _check_supported_idrac_version(self):
        idrac_cd_info = self._get(DELL.IDRAC_CD_PATH)

        if '#VirtualMedia.InsertMedia' not in idrac_cd_info['Actions'].keys() or '#VirtualMedia.EjectMedia' not in idrac_cd_info['Actions'].keys():
            raise BMCException('VirtualMedia not supported in BMC')

    def _wait_media_inserted(self, timeout=60):
        logging.debug('_wait_media_inserted called (timeout=%s)', timeout)

        if not self._wait_status(timeout, self._verify_media_inserted):
            raise BMCException('Virtual media not inserted in time')

    def _wait_media_ejected(self, timeout=60):
        logging.debug('_wait_media_ejected called (timeout=%s)', timeout)

        if not self._wait_status(timeout, self._verify_media_inserted, expected_state=False):
            raise BMCException('Virtual media not ejected in time')

    def _wait_status(self, timeout, verify_func, expected_state=True, args=None):
        if not args:
            args = []

        starttime = int(time.time()*1000)

        state = not expected_state
        while state is not expected_state:
            timenow = int(time.time()*1000)
            if timenow - starttime > timeout*1000:
                return False

            state = verify_func(*args)

            if state is not expected_state:
                time.sleep(5)

        return True

    def _verify_media_inserted(self):
        logging.debug('_verify_media_inserted called')

        data = self._get(DELL.IDRAC_CD_PATH)

        if not data['Inserted']:
            return False

        return True

    def _verify_task_completed(self, task_id):
        response = self._get(task_id)

        job_state = response['Oem']['Dell']['JobState']

        return job_state == 'Completed'

    def _verify_task_ok(self, task_id):
        response = self._get(task_id)

        task_message = response['Oem']['Dell']['Message']

        failures = ['failed', 'completed with errors', 'Not one', 'not compliant', 'Unable', 'The system could not be shut down', 'timed out']
        if any(failure in task_message for failure in failures):
            for message in response['Messages']:
                for item in message.items():
                    if item[0] == "Oem":
                        logging.debug('Failure details: %s', item[1]['Dell'])
                    else:
                        pass
            raise BMCException('Requested task did not succeed')
        elif 'No changes' in task_message:
            logging.debug('Requested settings already applied')

