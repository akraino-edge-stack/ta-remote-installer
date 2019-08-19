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

class BMCException(Exception):
    pass

class BMC(object):
    def __init__(self, host, user, passwd, priv_level='ADMINISTRATOR', log_path=None):
        self._host = host
        self._user = user
        self._passwd = passwd
        self._priv_level = priv_level
        if log_path:
            self._log_path = log_path
        else:
            self._log_path = 'console.log'
        self._sol = None
        self._host_name = None

    def set_host_name(self, host_name):
        if not self._host_name:
            self._host_name = host_name

    def get_host_name(self):
        if self._host_name:
            return self._host_name

        return '<NONAME>'

    def get_host(self):
        return self._host

    def get_user(self):
        return self._user

    def get_passwd(self):
        return self._passwd

    def get_priv_level(self):
        return self._priv_level
    
    def attach_virtual_cd(self, media_info):
        raise NotImplementedError

    def _set_boot_from_virtual_media(self):
        raise NotImplementedError

    def _detach_virtual_media(self):
        raise NotImplementedError

    def reset_bmc(self, timeout=180):
        logging.info('Reset BMC of %s: %s', self.get_host_name(), self.get_host())

        self._run_ipmitool_command('bmc reset cold')

        success = self._wait_for_bmc_reset(timeout)
        if not success:
            raise BMCException('BMC reset failed, BMC did not come up')

    def _wait_for_bmc_responding(self, timeout, expected_to_respond=True):
        if expected_to_respond:
            logging.debug('Wait for BMC to start responding')
        else:
            logging.debug('Wait for BMC to stop responding')

        start_time = int(time.time()*1000)

        response = (not expected_to_respond)
        while response != expected_to_respond:
            rc, _ = self._run_ipmitool_command('bmc info', can_fail=True)
            response = (rc == 0)

            if response == expected_to_respond:
                break

            time_now = int(time.time()*1000)
            if time_now-start_time > timeout*1000:
                logging.debug('Wait timed out')
                break

            logging.debug('Still waiting for BMC')
            time.sleep(10)

        return response == expected_to_respond

    def _wait_for_bmc_webpage(self, timeout):
        host = ipaddress.ip_address(unicode(self._host))
        if host.version == 6:
            host = "[%s]" %host

        command = 'curl -g --insecure -o /dev/null https://{}/index.html'.format(host)

        start_time = int(time.time()*1000)
        rc = 1
        while rc != 0:
            p = subprocess.Popen(command.split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            _, _ = p.communicate()
            rc = p.returncode

            if rc == 0:
                break

            time_now = int(time.time()*1000)
            if time_now-start_time > timeout*1000:
                logging.debug('Wait timed out')
                break

            logging.debug('Still waiting for BMC webpage')
            time.sleep(10)

        return rc == 0

    def _wait_for_bmc_not_responding(self, timeout):
        return self._wait_for_bmc_responding(timeout, False)

    def _wait_for_bmc_reset(self, timeout):
        logging.debug('Wait for BMC to reset')

        success = True
        if not self._wait_for_bmc_not_responding(timeout):
            success = False
            msg = 'BMC did not go down as expected'
            logging.warning(msg)
        else:
            logging.debug('As expected, BMC is not responding')

        if not self._wait_for_bmc_responding(timeout):
            success = False
            msg = 'BMC did not come up as expected'
            logging.warning(msg)
        else:
            logging.debug('As expected, BMC is responding')

        if not self._wait_for_bmc_webpage(timeout):
            success = False
            msg = 'BMC webpage did not start to respond'
            logging.warning(msg)
        else:
            logging.debug('As expected, BMC webpage is responding')

        return success

    def setup_boot_options_for_virtual_media(self):
        logging.debug('Setup boot options')

        self._disable_boot_flag_timeout()
        self._set_boot_from_virtual_media()

    def power(self, power_command):
        logging.debug('Run host power command (%s) %s', self._host, power_command)

        if power_command == 'on' or power_command == 'off':
            old_status = self.power('status')
            if old_status == 'Chassis Power is {}'.format(power_command):
                logging.debug('Power is already %s', power_command)
                return

        return self._run_ipmitool_command('power {}'.format(power_command)).strip()

    def wait_for_bootup(self):
        logging.debug('Wait for prompt after booting from hd')

        try:
            self._expect_flag_in_console('localhost login:', timeout=1200)
        except BMCException as ex:
            self._send_to_console('\n')
            self._expect_flag_in_console('localhost login:', timeout=30)

    def setup_sol(self):
        logging.debug('Setup SOL for %s', self._host)

        self._run_ipmitool_command('sol set non-volatile-bit-rate 115.2')
        self._run_ipmitool_command('sol set volatile-bit-rate 115.2')

    def boot_from_virtual_media(self):
        logging.info('Boot from virtual media')

        self._trigger_boot()
        self._wait_for_virtual_media_detach_phase()

        self._detach_virtual_media()
        self._set_boot_from_hd_no_boot()

        logging.info('Boot should continue from disk now')

    def close(self):
        if self._sol:
            self._sol.terminate()
        self._sol = None

    @staticmethod
    def _convert_to_hex(ascii_string, padding=False, length=0):
        hex_value = ''.join('0x{} '.format(c.encode('hex')) for c in ascii_string).strip()
        if padding and (len(ascii_string) < length):
            hex_value += ''.join(' 0x00' for _ in range(len(ascii_string), length))

        return hex_value

    @staticmethod
    def _convert_to_ascii(hex_string):
        return ''.join('{}'.format(c.decode('hex')) for c in hex_string)

    def _execute_ipmitool_command(self, ipmi_command):
        command = 'ipmitool -I lanplus -H {} -U {} -P {} -L {} {}'.format(self._host, self._user, self._passwd, self._priv_level, ipmi_command)

        p = subprocess.Popen(command.split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out, _ = p.communicate()
        rc = p.returncode

        return (rc, out)

    def _run_ipmitool_command(self, ipmi_command, can_fail=False, retries=5):
        logging.debug('Run ipmitool command: %s', ipmi_command)

        if can_fail:
            return self._execute_ipmitool_command(ipmi_command)
        else:
            while retries > 0:
                rc, out = self._execute_ipmitool_command(ipmi_command)
                if not rc:
                    break

                if retries > 0:
                    logging.debug('Retry command')
                    time.sleep(5)

                retries -= 1

            if rc:
                logging.warning('ipmitool failed: %s', out)
                raise BMCException('ipmitool call failed with rc: {}'.format(rc))

        return out

    def _run_ipmitool_raw_command(self, ipmi_raw_command):
        logging.debug('Run ipmitool raw command')

        out = self._run_ipmitool_command('raw {}'.format(ipmi_raw_command))

        out_bytes = out.replace('\n', '').strip().split(' ')
        return out_bytes

    def _disable_boot_flag_timeout(self):
        logging.debug('Disable boot flag timeout (%s)', self._host)

        status_code = self._run_ipmitool_raw_command('0x00 0x08 0x03 0x1f')
        if status_code[0] != '':
            raise BMCException('Could not disable boot flag timeout (rc={})'.format(status_code[0]))

    def _open_console(self):
        logging.debug('Open SOL console (log in %s)', self._log_path)

        expect_session = pexpect.spawn('ipmitool -I lanplus -H {} -U {} -P {} -L {} sol deactivate'.format(self._host, self._user, self._passwd, self._priv_level))
        expect_session.expect(pexpect.EOF)

        logfile = open(self._log_path, 'ab')

        expect_session = pexpect.spawn('ipmitool -I lanplus -H {} -U {} -P {} -L {} sol activate'.format(self._host, self._user, self._passwd, self._priv_level), timeout=None, logfile=logfile)

        return expect_session

    def _send_to_console(self, chars):
        logging.debug('Sending %s to console', chars.replace('\n', '\\n'))

        if not self._sol:
            self._sol = self._open_console()

        self._sol.send(chars)

    def _expect_flag_in_console(self, flags, timeout=600):
        logging.debug('Expect a flag in console output within %s seconds ("%s")', timeout, flags)

        time_begin = time.time()

        remaining_time = timeout

        while remaining_time > 0:
            if not self._sol:
                try:
                    self._sol = self._open_console()
                except pexpect.TIMEOUT as e:
                    logging.debug(e)
                    raise BMCException('Could not open console: {}'.format(str(e)))

            try:
                self._sol.expect(flags, timeout=remaining_time)
                logging.debug('Flag found in log')
                return
            except pexpect.TIMEOUT as e:
                logging.debug(e)
                raise BMCException('Expected message in console did not occur in time ({})'.format(flags))
            except pexpect.EOF as e:
                logging.warning('Got EOF from console')
                if 'SOL session closed by BMC' in self._sol.before:
                    logging.debug('Found: "SOL session closed by BMC" in console')
                elapsed_time = time.time()-time_begin
                remaining_time = timeout-elapsed_time
                if remaining_time > 0:
                    logging.info('Retry to expect a flag in console, %s seconds remaining', remaining_time)
                    self.close()

        raise BMCException('Expected message in console did not occur in time ({})'.format(flags))

    def _wait_for_bios_settings_done(self):
        logging.debug('Wait until BIOS settings are updated')

        self._expect_flag_in_console('Booting...', timeout=300)

    def _set_boot_from_hd_no_boot(self):
        logging.debug('Set boot from hd (%s), no boot', self._host)

        self._run_ipmitool_command('chassis bootdev disk options=persistent')

    def _wait_for_virtual_media_detach_phase(self):
        logging.debug('Wait until virtual media can be detached')

        self._expect_flag_in_console(['Copying cloud guest image',
                                      'Installing OS to HDD',
                                      'Extending partition and filesystem size'],
                                     timeout=1200)

    def _trigger_boot(self):
        logging.debug('Trigger boot')

        power_state = self.power('status')
        logging.debug('State is: %s', power_state)
        if power_state == 'Chassis Power is off':
            self.power('on')
        else:
            self.power('reset')
