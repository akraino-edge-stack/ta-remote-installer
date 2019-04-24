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

import sys
import argparse
import logging
import pexpect

class CatFileException(Exception):
    pass

class CatFile(object):
    def __init__(self, bmc_host, bmc_user, bmc_password, login_user, login_password):
        self._host = bmc_host
        self._user = bmc_user
        self._password = bmc_password
        self._sol = None

        self._login_user = login_user
        self._login_password = login_password

    def _open_console(self, log):
        logging.info('Open SOL console')

        logging.debug('deactivate sol')
        expect_session = pexpect.spawn('ipmitool -I lanplus -H {} -U {} -P {} sol deactivate'.format(self._host, self._user, self._password))
        expect_session.expect(pexpect.EOF)

        logging.debug('activate sol, output will go to %s', log)
        self._sol = pexpect.spawn('ipmitool -I lanplus -H {} -U {} -P {} sol activate'.format(self._host, self._user, self._password), timeout=None)
        logfile = open(log, 'wb')
        self._sol.logfile_read = logfile

    def _close_console(self):
        logging.info('Close SOL console')

        if self._sol:
            logging.debug('Logout from host')
            self._sol.sendline('logout\r\n')
            self._sol.sendline()
            self._sol.expect('login:', timeout=10)
            self._sol.terminate()

        logging.debug('deactivate sol')
        session = pexpect.spawn('ipmitool -I lanplus -H {} -U {} -P {} sol deactivate'.format(self._host, self._user, self._password))
        session.expect(pexpect.EOF)

    def _expect_cmd_prompt(self):
        self._sol.expect('# ', timeout=10)

    def _login(self):
        logging.info('Login to host')

        try:
            self._sol.sendline()

            self._expect_cmd_prompt()
            logging.debug('Command prompt found')

            return
        except pexpect.exceptions.TIMEOUT as e:
            pass

        try:
            self._sol.sendline()

            self._sol.expect('login:', timeout=10)
            logging.debug('Login prompt found')

            self._sol.sendline(self._login_user)

            self._sol.expect('Password:', timeout=10)
            logging.debug('Password prompt found')

            self._sol.sendline(self._login_password)

            self._sol.sendline()
            self._expect_cmd_prompt()
            logging.debug('Command prompt found')
        except pexpect.exceptions.TIMEOUT as e:
            logging.debug(e)
            raise

    def _cat_log(self, path, timeout=120):
        logging.debug('Catting %s', path)

        self._sol.sendline('cat {}; echo CONSOLE_CAT_DONE\r\n'.format(path))
        self._sol.expect('CONSOLE_CAT_DONE', timeout=timeout)
        logging.debug('Catting done')

        self._expect_cmd_prompt()

    def cat(self, path, log_file, timeout=None):
        try:
            self._open_console(log_file)
            self._login()
            self._cat_log(path, timeout)
            self._close_console()
        except Exception as ex:
            logging.warn('Cat file failed: %s', str(ex))
            raise CatFileException(str(ex))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-H', '--bmc_host', required=True, help='BMC host')
    parser.add_argument('-U', '--bmc_user', required=True, help='BMC user')
    parser.add_argument('-P', '--bmc_password', required=True, help='BMC user password')
    parser.add_argument('-u', '--user', required=True, help='Login user')
    parser.add_argument('-p', '--password', required=True, help='Login user password')
    parser.add_argument('-f', '--file', required=True, help='File path to cat')
    parser.add_argument('-o', '--output_file', required=True, help='Output file name of the log')
    parser.add_argument('-t', '--timeout', required=False, help='Timeout for catting the file')

    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG)

    cat_file = CatFile(args.bmc_host, args.bmc_user, args.bmc_password, args.user, args.password)
    cat_file.cat(args.file, args.output_file, args.password)

if __name__ == "__main__":
    sys.exit(main())
