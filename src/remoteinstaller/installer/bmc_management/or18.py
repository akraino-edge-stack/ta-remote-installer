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
from .bmctools import BMC

class BMCException(Exception):
    pass

class OR18(BMC):
    def __init__(self, host, user, passwd, log_path=None):
        super(OR18, self).__init__(host, user, passwd, log_path)

    def _clear_ris_configuration(self):
        # Clear RIS configuration
        try:
            logging.debug('Clear RIS configuration.')
            self._run_ipmitool_raw_command('0x32 0x9f 0x01 0x0d')
        except Exception as err:
            logging.warning('Exception when clearing RIS NFS configuration: %s', str(err))
            return False
        return True

    def _check_virtual_media_started(self):
        # check virtmedia service status
        try:
            out = self._run_ipmitool_raw_command('0x32 0xca 0x08')
            logging.debug('Virtual media service status: %s', str(out[0]))
        except Exception as err:
            logging.warning('Exception when checking virtual media service: %s', str(err))
        if out[0] == '01':
            return True
        return False

    def _start_virtual_media(self):
        # Enable "Remote Media Support" in GUI (p145)
        try:
            logging.debug('Start virtual media service')
            self._run_ipmitool_raw_command('0x32 0xcb 0x08 0x01')
        except Exception as err:
            logging.warning('Exception when starting virtual media service: %s', str(err))

    def _set_setup_nfs(self, nfs_host, mount_path):

        # Set share type NFS
        try:
            logging.debug('Virtual media share type to NFS.')
            self._run_ipmitool_raw_command('0x32 0x9f 0x01 0x05 0x00 0x6e 0x66 0x73 0x00 0x00 0x00')
        except Exception as err:
            logging.warning('Exception when setting virtual media service type NFS: %s', str(err))
            return False

        # NFS server IP
        try:
            cmd = '0x32 0x9f 0x01 0x02 0x00 %s' % (self._convert_to_hex(nfs_host, True, 63))
            logging.debug('Virtual media server "%s"', nfs_host)
            self._run_ipmitool_raw_command(cmd)
        except Exception as err:
            logging.warning('Exception when setting virtual media server: %s', str(err))
            return False

        # Set NFS Mount Root path
        try:
            logging.debug('Virtual media path to "%s"', mount_path)
            # set progress bit (hmm. seems to return error if it is already set.. So should check..)
            time.sleep(2)
            cmd = '0x32 0x9f 0x01 0x01 0x00 0x00'
            self._run_ipmitool_raw_command(cmd)
            time.sleep(2)
            cmd = '0x32 0x9f 0x01 0x01 0x00 0x01'
            self._run_ipmitool_raw_command(cmd)
            time.sleep(2)
            cmd = '0x32 0x9f 0x01 0x01 0x01 %s' % (self._convert_to_hex(mount_path, True, 64))
            self._run_ipmitool_raw_command(cmd)
            time.sleep(2)
            # clear progress bit
            cmd = '0x32 0x9f 0x01 0x01 0x00 0x00'
            self._run_ipmitool_raw_command(cmd)
        except Exception as err:
            logging.warning('Exception when setting virtual media path: %s', str(err))
            return False
        return True

    def _enable_virtual_media(self):
        logging.debug('Enable Virtual Media')

        # 0x32 0xcb command will cause vmedia service restart automatically after 2 seconds according doc.
        # restart is delayed by 2 seconds if new command is received during 2 second delay
        # In other words, do all config in batch and it will only be restarted once.

        # Speed up things if it service is already running
        if self._check_virtual_media_started():
            logging.debug('Virtual media service already running.')
            # Service is already started
            return True

        self._start_virtual_media()

        _max_tries = 6
        _try = 1
        # Just enabling the service doe not seem to start it (in all HW)
        # Resetting it after enabling helps
        self._restart_virtual_media_service()
        while not self._check_virtual_media_started():
            if _try > _max_tries:
                logging.warning('Ensure virtual media service start failed, attempts exceeded.')
                return False
            time.sleep(5)
            _try = _try + 1
        return True

    def _get_virtual_media_device_count(self, devicetype):
        try:
            _num_inst = 0
            # Get num of enabled devices
            if devicetype == 'CD':
                _devparam = '0x04'
                logging.debug('Get virtual CD count')
            elif devicetype == 'FD':
                _devparam = '0x05'
                logging.debug('Get virtual FD count')
            elif devicetype == 'HD':
                _devparam = '0x06'
                logging.debug('Get virtual HD count')
            else:
                logging.warning('Unknown device type "%s"', devicetype)
                return _num_inst

            cmd = '0x32 0xca %s' % _devparam
            out = self._run_ipmitool_raw_command(cmd)
            _num_inst = int(out[0], 16)

            logging.debug('Number of enabled %s devices is %d', devicetype, _num_inst)

            return _num_inst
        except Exception as err:
            raise BMCException('Exception when getting number of enabled %s devices. error: %s' % (devicetype, str(err)))

    def _set_virtual_media_device_count(self, devicetype, devicecount):
        # Chapter 46.2 page 181
        if not 0 <= devicecount <= 4:
            logging.warning('Number of devices must be in range 0 to 4')
            return False

        if devicetype == 'CD':
            _devparam = '0x04'
            logging.debug('Setting virtual CD count to %d', devicecount)
        elif devicetype == 'HD':
            _devparam = '0x06'
            logging.debug('Setting virtual HD count to %d', devicecount)
        else:
            logging.warning('_set_virtual_media_device_count: Unknown device type "%s"', devicetype)
            return False

        try:
            cmd = '0x32 0xcb %s 0x%s' % (_devparam, str(devicecount))
            self._run_ipmitool_raw_command(cmd)

            _conf_device_num = self._get_virtual_media_device_count(devicetype)
            _tries = 4
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
            cmd = '0x32 0xcb 0x0a 0x01'
            logging.debug('Restart virtual media service')
            self._run_ipmitool_raw_command(cmd)
        except Exception as err:
            raise BMCException('Exception when restarting virtual media service: %s' % str(err))

    def _restart_ris(self):
        try:
            logging.debug('Restart RIS')
            cmd = '0x32 0x9f 0x08 0x0b'
            self._run_ipmitool_raw_command(cmd)
        except Exception as err:
            raise BMCException('Exception when restarting RIS: %s'% str(err))

        return True

    def _restart_ris_cd(self):
        try:
            logging.debug('Restart RIS CD media')
            cmd = '0x32 0x9f 0x01 0x0b 0x01'
            self._run_ipmitool_raw_command(cmd)
        except Exception as err:
            raise BMCException('Exception when restarting RIS CD media: %s' % str(err))

        return True

    def _check_cd_dvd_enabled(self, enabled):
        try:
            out = self._run_ipmitool_raw_command('0x32 0xca 0x0')
            logging.debug('Virtual cd_dvd status: %s', str(out[0]))
        except Exception as err:
            logging.warning('Exception when checking cd_dvd status: %s', str(err))
        if (out[0] == '01' and enabled) or (out[0] == '00' and not enabled):
            return True
        return False

    def _enable_disable_cd_dvd(self, enabled):
        _max_tries = 6
        _try = 1
        logging.debug('Enable/Disable cd_dvd')
        while not self._check_cd_dvd_enabled(enabled):
            if _try > _max_tries:
                logging.warning('Ensure cd_dvd enable/disable failed, attempts exceeded. Ignoring and trying to continue.')
                return True
            time.sleep(5)
            _try = _try + 1
        return True

    def _toggle_virtual_device(self, enabled):
        # Enable "Mount CD/DVD" in GUI (p144) should cause vmedia restart withing 2 seconds.
        # Seems "Mount CD/DVD" need to be enabled (or toggled) after config. refresh/vmedia restart
        # is not enough(?)
        try:
            logging.debug('Enable/Disable mount CD/DVD.')
            time.sleep(1)
            #This will fail with new firmware on OR18
            self._run_ipmitool_raw_command('0x32 0xcb 0x00 0x0%s' %(str(int(enabled))))
            return self._enable_disable_cd_dvd(enabled)
        except Exception as err:
            logging.warning('Exception when CD/DVD virtual media new firmware? ignoring... Error: %s', str(err))
        return True

    def _mount_virtual_device(self):
        return self._toggle_virtual_device(True)

    def _demount_virtual_device(self):
        return self._toggle_virtual_device(False)

    def _get_mounted_image_count(self):
        count = 0
        try:
            out = self._run_ipmitool_raw_command('0x32 0xd8 0x00 0x01')
            count = int(out[1], 16)
            logging.warning('Available image count: %d', count)
        except Exception as err:
            logging.warning('Exception when trying to get the image count: %s', str(err))
        return count

    def _wait_for_mount_count(self):
        # Poll until we got some images from server
        _max_tries = 12
        _try = 1
        while self._get_mounted_image_count() == 0:
            logging.debug('Check available images count try %d/%d', _try, _max_tries)
            if _try > _max_tries:
                logging.warning('Available images count 0, attempts exceeded.')
                return False
            time.sleep(10)
            _try = _try + 1
        return True

    def _set_image_name(self, image_filename):
        try:
            logging.debug('Setting virtual media image: %s', image_filename)
            self._run_ipmitool_raw_command('0x32 0xd7 0x01 0x01 0x01 0x01 %s' % (self._convert_to_hex(image_filename, True, 64)))
        except Exception as err:
            logging.debug('Exception when setting virtual media image: %s', str(err))
            return False
        return True

    def _get_bmc_nfs_service_status(self):
        # Check NFS Service Status
        try:
            out = self._run_ipmitool_raw_command('0x32 0xd8 0x06 0x01 0x01 0x00')
            _image_name = str(bytearray.fromhex(''.join(out)))
            return 'mounted'
        except Exception:
            return 'nfserror'

    def _stop_remote_redirection(self):
        # Get num of enabled devices
        _num_inst = self._get_virtual_media_device_count('CD')
        for driveindex in range(0, _num_inst):
            cmd = '0x32 0xd7 0x00 0x01 0x01 0x00 %s' % hex(driveindex)
            logging.debug('Stop redirection CD/DVD drive index %d', driveindex)
            try:
                out = self._run_ipmitool_raw_command(cmd)
                logging.debug('ipmitool out = %s', (out))
            except Exception as err:
                # Drive might not be mounted to start with
                logging.debug('_stop_remote_redirection: Ignoring exception when stopping redirection CD/DVD drive index %d error: %s', driveindex, str(err))

    def _set_boot_from_virtual_media(self):
        logging.debug('Set boot from cd (%s), and boot after that', self._host)
        self._run_ipmitool_command('chassis bootdev cdrom options=persistent')

        #logging.debug('Set boot from cd (%s), and boot after that', self._host)
        #try:
        #    self._run_ipmitool_raw_command('0x00 0x08 0x05 0xC0 0x20 0x00 0x00 0x00')
        #except Exception as err:
        #    logging.warning('Set Boot to CD failed: %s' % str(err))
        #    raise BMCException('Set Boot to CD failed')

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

    def attach_virtual_cd(self, nfs_host, nfs_mount, boot_iso_filename):
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
            raise BMCException("Failed to setup nfs")

        # Restart Remote Image CD
        if not self._restart_ris_cd():
            raise BMCException("Failed to restart RIS CD")

        #Wait for device to be mounted
        if not self._wait_for_mount_count():
            raise BMCException("Failed when waiting for the device to appear")

        # Set Image Name
        time.sleep(2)
        if not self._set_image_name(boot_iso_filename):
            raise BMCException("Failed to set image name")

        success = self._wait_for_bmc_nfs_service(90, 'mounted')
        if success:
            return True
        else:
            raise BMCException('NFS service setup failed')
