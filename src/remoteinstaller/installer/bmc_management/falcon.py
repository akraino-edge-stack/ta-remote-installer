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

import logging
import time
from .bmctools import BMC, BMCException

RAW_CHECK_NFS_SERVICE_STATUS = '0x32 0xd8 0x06 0x01 0x01 0x00'

RAW_GET_VMEDIA_DEVICE_COUNT = '0x32 0xca %s'     # (type)
RAW_SET_VMEDIA_DEVICE_COUNT = '0x32 0xcb %s %s'  # (type, count)
( VMEDIA_DEVICE_TYPE_CD,
  VMEDIA_DEVICE_TYPE_FD,
  VMEDIA_DEVICE_TYPE_HD ) = ('0x04', '0x05', '0x06')

RAW_GET_VMEDIA_MOUNT_STATUS = '0x32 0xca 0x00'
RAW_SET_VMEDIA_MOUNT_STATUS = '0x32 0xcb 0x00 %s'

RAW_GET_VMEDIA_STATUS = '0x32 0xca 0x08'
RAW_SET_VMEDIA_STATUS = '0x32 0xcb 0x08 %s'
RAW_RESTART_VMEDIA =    '0x32 0xcb 0x0a 0x01'

# Remote Image Service commands
RAW_RESTART_RIS_CD =   '0x32 0x9f 0x01 0x0b 0x01'
RAW_SET_RIS_NFS =      '0x32 0x9f 0x01 0x05 0x00 0x6e 0x66 0x73 0x00 0x00 0x00'
RAW_SET_RIS_NFS_IP =   '0x32 0x9f 0x01 0x02 0x00 %s'
RAW_SET_RIS_NFS_PATH = '0x32 0x9f 0x01 0x01 0x01 %s'
RAW_SET_RIS_PROGRESS = '0x32 0x9f 0x01 0x01 0x00 %s'
RAW_CLEAR_RIS_CONFIG = '0x32 0x9f 0x01 0x0d'
RAW_RESTART_RIS =      '0x32 0x9f 0x08 0x0b'

RAW_GET_MOUNTED_IMG_COUNT = '0x32 0xd8 0x00 0x01'
RAW_SET_IMG_NAME =  '0x32 0xd7 0x01 0x01 0x01 0x01 %s'
RAW_STOP_REDIRECT = '0x32 0xd7 0x01 0x01 0x01 0x00 %s'

class FALCON(BMC):
    def __init__(self, host, user, passwd, priv_level='ADMINISTRATOR', log_path=None):
        super(FALCON, self).__init__(host, user, passwd, priv_level, log_path)

    def _clear_ris_configuration(self):
        # Clear Remote Image Service configuration
        try:
            logging.debug('Clear RIS configuration.')
            self._run_ipmitool_raw_command(RAW_CLEAR_RIS_CONFIG)
        except Exception as err:
            logging.warning('Exception when clearing RIS NFS configuration: %s', str(err))
            return False
        return True

    def _check_virtual_media_started(self):
        # Check virtmedia service status
        try:
            out = self._run_ipmitool_raw_command(RAW_GET_VMEDIA_STATUS)
            service_status = out[0]
            logging.debug('Virtual media service status: %s', service_status)
        except Exception as err:
            logging.warning('Exception when checking virtual media service: %s', str(err))

        return service_status == '01'

    def _start_virtual_media(self):
        # Enable "Remote Media Support" in GUI (p145)
        try:
            logging.debug('Start virtual media service')
            self._run_ipmitool_raw_command(RAW_SET_VMEDIA_STATUS % '0x01')
        except Exception as err:
            logging.warning('Exception when starting virtual media service: %s', str(err))

    def _set_setup_nfs(self, nfs_host, mount_path):

        # Set share type NFS
        try:
            logging.debug('Virtual media share type to NFS.')
            self._run_ipmitool_raw_command(RAW_SET_RIS_NFS)
        except Exception as err:
            logging.warning('Exception when setting virtual media service type NFS: %s', str(err))
            return False

        # NFS server IP
        try:
            cmd = RAW_SET_RIS_NFS_IP % (self._convert_to_hex(nfs_host, True, 63))
            logging.debug('Virtual media server "%s"', nfs_host)
            self._run_ipmitool_raw_command(cmd)
        except Exception as err:
            logging.warning('Exception when setting virtual media server: %s', str(err))
            return False

        # Set NFS Mount Root path
        try:
            logging.debug('Virtual media path to "%s"', mount_path)

            self._run_ipmitool_raw_command(RAW_SET_RIS_PROGRESS % '0x00')
            time.sleep(2)
            self._run_ipmitool_raw_command(RAW_SET_RIS_PROGRESS % '0x01')
            time.sleep(2)
            self._run_ipmitool_raw_command(RAW_SET_RIS_NFS_PATH % (self._convert_to_hex(mount_path, True, 64)))
            time.sleep(2)
            self._run_ipmitool_raw_command(RAW_SET_RIS_PROGRESS % '0x00')

        except Exception as err:
            logging.warning('Exception when setting virtual media path: %s', str(err))
            return False
        return True

    def _enable_virtual_media(self):
        # Speed up things if it service is already running
        if self._check_virtual_media_started():
            logging.debug('Virtual media service already running.')
            return True

        # Just enabling the service does not seem to start it (in all HW)
        # Resetting it after enabling helps
        self._start_virtual_media()
        self._restart_virtual_media_service()

        tries = 60
        while tries > 0:
            if self._check_virtual_media_started():
                return True
            time.sleep(5)
            tries -= 1

        logging.warning('Ensure virtual media service start failed: attempts exceeded.')
        return False

    def _get_virtual_media_device_count(self, devicetype):
        try:
            _num_inst = 0
            # Get num of enabled devices
            if devicetype == 'CD':
                _devparam = VMEDIA_DEVICE_TYPE_CD
                logging.debug('Get virtual CD count')
            elif devicetype == 'FD':
                _devparam = VMEDIA_DEVICE_TYPE_FD
                logging.debug('Get virtual FD count')
            elif devicetype == 'HD':
                _devparam = VMEDIA_DEVICE_TYPE_HD
                logging.debug('Get virtual HD count')
            else:
                logging.warning('Unknown device type "%s"', devicetype)
                return _num_inst

            cmd = RAW_GET_VMEDIA_DEVICE_COUNT % _devparam
            out = self._run_ipmitool_raw_command(cmd)
            _num_inst = int(out[0], 16)
            logging.debug('Number of enabled %s devices is %d', devicetype, _num_inst)
            return _num_inst
        except Exception as err:
            raise BMCException('Exception when getting number of enabled %s devices. error: %s' % (devicetype, str(err)))

    def _set_virtual_media_device_count(self, devicetype, devicecount):
        if not 0 <= devicecount <= 4:
            logging.warning('Number of devices must be in range 0 to 4')
            return False

        if devicetype == 'CD':
            _devparam = VMEDIA_DEVICE_TYPE_CD
            logging.debug('Setting virtual CD count to %d', devicecount)
        elif devicetype == 'HD':
            _devparam = VMEDIA_DEVICE_TYPE_HD
            logging.debug('Setting virtual HD count to %d', devicecount)
        else:
            logging.warning('Unknown device type "%s"', devicetype)
            return False

        try:
            cmd = RAW_SET_VMEDIA_DEVICE_COUNT % (_devparam, hex(devicecount))
            self._run_ipmitool_raw_command(cmd)

            _conf_device_num = self._get_virtual_media_device_count(devicetype)
            _tries = 40
            while _conf_device_num != devicecount and _tries > 0:
                logging.debug('Virtual %s count is %d expecting %d', devicetype, _conf_device_num, devicecount)
                time.sleep(5)
                _conf_device_num = self._get_virtual_media_device_count(devicetype)
                _tries = _tries -1

        except Exception as err:
            raise BMCException('Exception when setting virtual media device count : %s' % str(err))
        return True

    def _restart_virtual_media_service(self):
        try:
            cmd = RAW_RESTART_VMEDIA
            logging.debug('Restart virtual media service')
            self._run_ipmitool_raw_command(cmd)
        except Exception as err:
            raise BMCException('Exception when restarting virtual media service: %s' % str(err))

    def _restart_ris(self):
        try:
            cmd = RAW_RESTART_RIS
            logging.debug('Restart RIS')
            self._run_ipmitool_raw_command(cmd)
        except Exception as err:
            raise BMCException('Exception when restarting RIS: %s' % str(err))

        return True

    def _restart_ris_cd(self):
        try:
            cmd = RAW_RESTART_RIS_CD
            logging.debug('Restart RIS CD media')
            self._run_ipmitool_raw_command(cmd)
        except Exception as err:
            raise BMCException('Exception when restarting RIS CD media: %s' % str(err))

        return True

    def _check_vmedia_mount_state(self, enabled):
        expected_state = 'enabled' if enabled else 'disabled'
        logging.debug('Check if CD/DVD device is %s', expected_state)

        tries = 10
        while tries > 0:
            try:
                out = self._run_ipmitool_raw_command(RAW_GET_VMEDIA_MOUNT_STATUS)
                status = out[0]
                logging.debug('Virtual media mount status: %s', status)
            except Exception as err:
                status = None
                logging.warning('Exception when checking VMedia mount status: %s', str(err))

            matched_state = (status == '01') if enabled else (status == '00')
            if matched_state:
                # Virtual media mount found in expected state
                return True

            tries -= 1
            time.sleep(6)

        logging.warning('Failed: CD/DVD mount is not %s (attempts exceeded).'
                        'Ignoring and trying to continue.',
                        expected_state)
        return False

    def _toggle_virtual_device(self, enabled):
        state_raw = '0x01' if enabled else '0x00'
        state_str = 'enable' if enabled else 'disable'

        logging.debug('Try to %s VMedia mount.', state_str)
        try:
            self._run_ipmitool_raw_command(RAW_SET_VMEDIA_MOUNT_STATUS % state_raw)
            time.sleep(1)
            return self._check_vmedia_mount_state(enabled)
        except Exception as err:
            logging.warning('Exception when tying to %s VMedia mount: %s. Ignoring... ',
                            state_str, str(err))
        return True

    def _mount_virtual_device(self):
        return self._toggle_virtual_device(True)

    def _demount_virtual_device(self):
        return self._toggle_virtual_device(False)

    def _get_mounted_image_count(self):
        count = 0
        try:
            out = self._run_ipmitool_raw_command(RAW_GET_MOUNTED_IMG_COUNT)
            count = int(out[0], 16)
            logging.warning('Available image count: %d', count)
        except Exception as err:
            logging.warning('Exception when trying to get the image count: %s', str(err))
        return count

    def _wait_for_mount_count(self):
        # Poll until we got some images from server
        tries = 12
        while tries > 0:
            if self._get_mounted_image_count() > 0:
                return True
            tries -= 1
            logging.debug('Check available images count tries left: %d', tries)
            time.sleep(10)

        logging.warning('Available images count 0, attempts exceeded.')
        return False

    def _set_image_name(self, image_filename):
        try:
            logging.debug('Setting virtual media image: %s', image_filename)
            self._run_ipmitool_raw_command(RAW_SET_IMG_NAME % self._convert_to_hex(image_filename, True, 64))
        except Exception as err:
            logging.warning('Exception when setting virtual media image: %s', str(err))
            return False
        return True

    def _get_bmc_nfs_service_status(self):
        try:
            out = self._run_ipmitool_raw_command(RAW_CHECK_NFS_SERVICE_STATUS)
            _image_name = str(bytearray.fromhex(''.join(out)))
            logging.debug('Found mounted image: %s', _image_name)
            return 'mounted'
        except Exception:
            return 'nfserror'

    def _stop_remote_redirection(self):
        _num_inst = self._get_virtual_media_device_count('CD')
        for driveindex in range(0, _num_inst):
            cmd = RAW_STOP_REDIRECT % hex(driveindex)
            logging.debug('Stop redirection CD/DVD drive index %d', driveindex)
            try:
                out = self._run_ipmitool_raw_command(cmd)
                logging.debug('ipmitool out = "%s"', out)
            except Exception as err:
                # Drive might not be mounted to start with
                logging.debug('Ignoring exception when stopping redirection CD/DVD drive index %d error: %s',
                              driveindex, str(err))

    def _set_boot_from_virtual_media(self):
        logging.debug('Set boot from cd (%s), and boot after that', self._host)
        try:
            self._run_ipmitool_command('chassis bootdev floppy options=persistent')
        except Exception as err:
            raise BMCException('Set Boot to CD failed: %s' % str(err))

    def _detach_virtual_media(self):
        logging.debug('Detach virtual media')

        #Enable virtual media
        if not self._enable_virtual_media():
            raise BMCException("detach_virtual_cd: Failed to enable virtual media")

        # Restart Remote Image Service
        if not self._restart_ris():
            raise BMCException("Failed to restart RIS")

        # Stop redirection
        self._stop_remote_redirection()

        #Clear RIS configuration
        if not self._clear_ris_configuration():
            raise BMCException("detach_virtual_cd: Failed to clear RIS configuration")

        #Demount virtual device
        if not self._demount_virtual_device():
            raise BMCException('detach_virtual_cd: Exception when disabling CD/DVD virtual media')

        # Reduce the number of virtual devices (both HD and CD default to 4 devices each)
        if not self._set_virtual_media_device_count('HD', 0):
            BMCException('Failed to set virtual media device count for HD')
        if not self._set_virtual_media_device_count('CD', 1):
            BMCException('Failed to set virtual media device count for CD')

    def try_attach_virtual_cd(self, nfs_host, nfs_mount, boot_iso_filename):
        # Detach first
        self._detach_virtual_media()

        logging.debug('Attach virtual media')

        #Enable virtual media
        if not self._enable_virtual_media():
            raise BMCException("Failed to enable virtual media")

        #Enable CD/DVD device
        if not self._toggle_virtual_device(True):
            raise BMCException("Failed to enable virtual device")

        #Clear RIS configuration
        if not self._clear_ris_configuration():
            raise BMCException("Failed to clear RIS configuration")

        #Setup nfs
        if not self._set_setup_nfs(nfs_host, nfs_mount):
            raise BMCException("Failed to setup NFS")

        # Restart Remote Image CD
        if not self._restart_ris_cd():
            raise BMCException("Failed to restart RIS CD")

        #Wait for device to be mounted
        if not self._wait_for_mount_count():
            raise BMCException("Failed when waiting for the device to appear")

        # Set Image Name
        time.sleep(5)
        if not self._set_image_name(boot_iso_filename):
            raise BMCException("Failed to set image name")

        if not self._wait_for_bmc_nfs_service(90, 'mounted'):
            raise BMCException("NFS service setup failed")

        logging.debug("Virtual Media setup succeeded for nfs://%s/%s/%s",
                  nfs_host, nfs_mount, boot_iso_filename)
        return True

    def attach_virtual_cd(self, nfs_host, nfs_mount, boot_iso_filename):
        tries = 5
        while tries > 0:
            try:
                if self.try_attach_virtual_cd(nfs_host, nfs_mount, boot_iso_filename):
                    return True
            except Exception as err:
                tries -= 1
                logging.warning("Failed with exception: '%s'. %d tries remaining.",
                            str(err), tries)
                if tries <= 0:
                    raise err

        return False
