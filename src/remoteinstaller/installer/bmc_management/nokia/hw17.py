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

from ..bmctools import BMCException
from .nokia import NokiaHW

class HW17(NokiaHW):
    def __init__(self, host, user, passwd, priv_level='ADMINISTRATOR', log_path=None):
        super(HW17, self).__init__(host, user, passwd, priv_level, log_path)

    def attach_virtual_cd(self, media_info):
        nfs_host = media_info['server']
        nfs_mount = media_info['path']
        boot_iso_filename = media_info['image']

        for _ in range(2):
            self._setup_bmc_nfs_service(nfs_host, nfs_mount, boot_iso_filename)
            success = self._wait_for_bmc_nfs_service(90, 'mounted')
            if success:
                return True
            else:
                logging.debug('BMC NFS server did not start yet')
                self.reset_bmc()

        raise BMCException('NFS service setup failed')

    def _detach_virtual_media(self):
        logging.debug('Detach virtual media')

        comp_code = self._run_ipmitool_raw_command('0x3c 0x00')
        if comp_code[0] == '80':
            raise BMCException('BMC NFS service reset failed, cannot get configuration')
        elif comp_code[0] == '81':
            raise BMCException('BMC NFS service reset failed, cannot set configuration')
        else:
            BMCException('BMC NFS service reset failed (rc={})'.format(comp_code))

    def _set_boot_from_virtual_media(self):
        logging.debug('Set boot from cd (%s), and boot after that', self._host)
        self._run_ipmitool_command('chassis bootdev floppy options=persistent')

    def _get_bmc_nfs_service_status(self):
        logging.debug('Get BMC NFS service status')

        status_code = self._run_ipmitool_raw_command('0x3c 0x03')
        if status_code[0] == '00':
            status = 'mounted'
        elif status_code[0] == '64':
            status = 'mounting'
        elif status_code[0] == 'ff':
            status = 'dismounted'
        elif status_code[0] == '20':
            status = 'nfserror'
        else:
            raise BMCException('Could not get BMC NFS service status (rc={})'.format(status_code))

        logging.debug('Returned status: %s', status)
        return status

    def _set_bmc_nfs_configuration(self, nfs_host, mount_path, image_name):
        logging.debug('Set BMC NFS configuration')

        nfs_host_hex = self._convert_to_hex(nfs_host)
        mount_path_hex = self._convert_to_hex(mount_path)
        image_name_hex = self._convert_to_hex(image_name)

        logging.debug('Set the IP address of the BMC NFS service (%s)', self._host)
        comp_code = self._run_ipmitool_raw_command('0x3c 0x01 0x00 {} 0x00'.format(nfs_host_hex))
        if comp_code[0] != '':
            raise BMCException('Failed to set BMC NFS service IP address (rc={})'.format(comp_code))

        logging.debug('Set the path of the BMC NFS service (%s)', mount_path)
        comp_code = self._run_ipmitool_raw_command('0x3c 0x01 0x01 {} 0x00'.format(mount_path_hex))
        if comp_code[0] != '':
            raise BMCException('Failed to set BMC NFS service path (rc={})'.format(comp_code))

        logging.debug('Set the ISO image name of the BMC NFS service (%s)', image_name)
        comp_code = self._run_ipmitool_raw_command('0x3c 0x01 0x02 {} 0x00'.format(image_name_hex))
        if comp_code[0] != '':
            raise BMCException('Failed to set BMC NFS service iso image name (rc={})'.format(comp_code))

    def _setup_bmc_nfs_service(self, nfs_host, mount_path, image_name):
        logging.debug('Setup BMC NFS service')

        self._detach_virtual_media()
        self._set_bmc_nfs_configuration(nfs_host, mount_path, image_name)

        logging.debug('Start the BMC NFS service')
        comp_code = self._run_ipmitool_raw_command('0x3c 0x02 0x01')
        if comp_code[0] != '':
            raise BMCException('Failed to start the BMC NFS service (rc={})'.format(comp_code))

