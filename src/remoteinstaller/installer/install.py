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
import sys
import argparse
import subprocess
import os
import importlib
import time

from yaml import load
from netaddr import IPNetwork
from netaddr import IPAddress

import hw_detector.hw_detect_lib as hw_detect
from hw_detector.hw_exception import HWException
from remoteinstaller.installer.bmc_management.bmctools import BMCException
from remoteinstaller.installer.catfile import CatFile
from remoteinstaller.installer.catfile import CatFileException

class InstallException(Exception):
    pass

class Installer(object):
    SSH_OPTS = '-o StrictHostKeyChecking=no \
                -o UserKnownHostsFile=/dev/null \
                -o ServerAliveInterval=60'

    def __init__(self, args):
        self._yaml_path = args.yaml
        self._boot_iso_path = args.boot_iso
        self._iso_url = args.iso
        self._logdir = args.logdir
        self._callback_url = args.callback_url
        self._client_key = args.client_key
        self._client_cert = args.client_cert
        self._ca_cert = args.ca_cert
        self._own_ip = args.host_ip
        self._tag = args.tag
        self._http_port = args.http_port

        # TODO
        self._disable_bmc_initial_reset = True
        self._disable_other_bmc_reset = True

        self._uc = self._read_user_config(self._yaml_path)
        self._vip = None
        self._first_controller_ip = None
        self._first_controller_bmc = None

    @staticmethod
    def _read_user_config(config_file_path):
        logging.debug('Read user config from %s', config_file_path)

        try:
            with open(config_file_path, 'r') as f:
                y = load(f)

            return y
        except Exception as ex:
            raise InstallException(str(ex))

    @staticmethod
    def _execute_shell(command, desc=''):
        logging.debug('Execute %s with command: %s', desc, command)

        p = subprocess.Popen(command.split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out, _ = p.communicate()
        if p.returncode:
            logging.warning('Failed to %s: %s (rc=%s)', desc, out, p.returncode)
            raise InstallException('Failed to {}'.format(desc))

        return (p.returncode, out)

    def _attach_iso_as_virtual_media(self, file_list):
        logging.info('Attach ISO as virtual media')

        nfs_mount = os.path.dirname(self._boot_iso_path)
        boot_iso_filename = os.path.basename(self._boot_iso_path)
        patched_iso_filename = '{}/{}_{}'.format(nfs_mount, self._tag, boot_iso_filename)

        self._patch_iso(patched_iso_filename, file_list)

        self._first_controller_bmc.attach_virtual_cd(self._own_ip, nfs_mount, os.path.basename(patched_iso_filename))

    def _create_cloud_config(self, first_controller):
        logging.info('Create network config file')

        domain = self._uc['hosts'][first_controller].get('network_domain')
        extnet = self._uc['networking']['infra_external']['network_domains'][domain]

        vlan = extnet.get('vlan')
        first_ip = extnet['ip_range_start']
        gateway = extnet['gateway']
        dns = self._uc['networking']['dns'][0]
        cidr = extnet['cidr']
        prefix = IPNetwork(cidr).prefixlen

        self._vip = str(IPAddress(first_ip))

        pre_allocated_ips = self._uc['hosts'][first_controller].get('pre_allocated_ips', None)
        if pre_allocated_ips:
            pre_allocated_infra_external_ip = pre_allocated_ips.get('infra_external', None)
            self._first_controller_ip = str(IPAddress(pre_allocated_infra_external_ip))

        if not self._first_controller_ip:
            self._first_controller_ip = str(IPAddress(first_ip)+1)

        controller_network_profile = self._uc['hosts'][first_controller]['network_profiles'][0]
        mappings = self._uc['network_profiles'][controller_network_profile]['interface_net_mapping']
        for interface in mappings:
            if 'infra_external' in mappings[interface]:
                infra_external_interface = interface
                break

        if infra_external_interface.startswith('bond'):
            bonds = self._uc['network_profiles'][controller_network_profile]['bonding_interfaces']
            device = bonds[infra_external_interface][0]
        else:
            device = infra_external_interface

        # TODO
        # ROOTFS_DISK

        logging.debug('VLAN=%s', vlan)
        logging.debug('DEV=%s', device)
        logging.debug('IP=%s/%s', self._first_controller_ip, prefix)
        logging.debug('DGW=%s', gateway)
        logging.debug('NAMESERVER=%s', dns)
        logging.debug('ISO_URL="%s"', self._iso_url)

        network_config_filename = '{}/network_config'.format(os.getcwd())
        with open(network_config_filename, 'w') as f:
            if vlan:
                f.write('VLAN={}\n'.format(vlan))
            f.write('DEV={}\n'.format(device))
            f.write('IP={}/{}\n'.format(self._first_controller_ip, prefix))
            f.write('DGW={}\n'.format(gateway))
            f.write('NAMESERVER={}\n'.format(dns))
            f.write('\n')
            f.write('ISO_URL="{}"'.format(self._iso_url))

        logging.debug('CALLBACK_URL="%s"', self._callback_url)

        callback_url_filename = '{}/callback_url'.format(os.getcwd())
        with open(callback_url_filename, 'w') as f:
            f.write(self._callback_url)

        if self._client_cert:
            return [self._yaml_path,
                    network_config_filename,
                    callback_url_filename,
                    self._client_key,
                    self._client_cert,
                    self._ca_cert]

        return [self._yaml_path,
                network_config_filename,
                callback_url_filename]

    def _patch_iso(self, iso_target, file_list):
        logging.info('Patch boot ISO')
        logging.debug('Original ISO: %s', self._boot_iso_path)
        logging.debug('Target ISO: %s', iso_target)

        file_list_str = ' '.join(file_list)
        logging.debug('Files to add: %s', file_list_str)

        self._execute_shell('/usr/bin/patchiso.sh {} {} {}'.format(self._boot_iso_path,
                                                                   iso_target,
                                                                   file_list_str), 'patch ISO')

    def _put_file(self, ip, user, passwd, file_name, to_file=''):
        self._execute_shell('sshpass -p {} scp {} {} {}@{}:{}'.format(passwd,
                                                                      Installer.SSH_OPTS,
                                                                      file_name,
                                                                      user,
                                                                      ip,
                                                                      to_file))

    def _get_file(self, log_dir, ip, user, passwd, file_name, recursive=False):
        if recursive:
            self._execute_shell('sshpass -p {} scp {} -r {}@{}:{} {}'.format(passwd,
                                                                             Installer.SSH_OPTS,
                                                                             user,
                                                                             ip,
                                                                             file_name,
                                                                             log_dir))
        else:
            self._execute_shell('sshpass -p {} scp {} {}@{}:{} {}'.format(passwd,
                                                                          Installer.SSH_OPTS,
                                                                          user,
                                                                          ip,
                                                                          file_name,
                                                                          log_dir))

    def _get_node_logs(self, log_dir, ip, user, passwd):
        self._get_file(log_dir, ip, user, passwd, '/srv/deployment/log/cm.log')
        self._get_file(log_dir, ip, user, passwd, '/srv/deployment/log/bootstrap.log')
        self._get_file(log_dir, ip, user, passwd, '/var/log/ironic', recursive=True)

    def _get_journal_logs(self, log_dir, ip, user, passwd):
        self._put_file(ip, user, passwd, '/opt/remoteinstaller/get_journals.sh')
        self._put_file(ip, user, passwd, '/opt/remoteinstaller/print_hosts.py')

        self._execute_shell('sh ./get_journals.sh')

        self._get_file(log_dir, ip, user, passwd, '/tmp/node_journals.tgz')

    def _get_logs_from_console(self, log_dir, bmc, admin_user, admin_passwd):
        bmc_host = bmc.get_host()
        bmc_user = bmc.get_user()
        bmc_passwd = bmc.get_passwd()

        log_file = '{}/cat_bootstrap.log'.format(log_dir)
        try:
            cat_file = CatFile(bmc_host, bmc_user, bmc_passwd, admin_user, admin_passwd)
            cat_file.cat('/srv/deployment/log/bootstrap.log', log_file)
        except CatFileException as ex:
            logging.info('Could not cat file from console: %s', str(ex))

            cat_file = CatFile(bmc_host, bmc_user, bmc_passwd, 'root', 'root')
            cat_file.cat('/srv/deployment/log/bootstrap.log', log_file)

    def get_logs(self, log_dir, admin_passwd):
        admin_user = self._uc['users']['admin_user_name']

        ssh_command = 'nc -w1 {} 22 </dev/null &> /dev/null'.format(self._first_controller_ip)
        ssh_responds = self._execute_shell(ssh_command)

        if ssh_responds:
            self._get_node_logs(log_dir, self._first_controller_ip, admin_user, admin_passwd)

            self._get_journal_logs(log_dir, self._first_controller_ip, admin_user, admin_passwd)
        else:
            self._get_logs_from_console(log_dir,
                                        self._first_controller_bmc,
                                        admin_user,
                                        admin_passwd)

    def install(self):
        try:
            logging.info('Start install')

            if os.path.dirname(self._boot_iso_path) == '':
                self._boot_iso_path = '{}/{}'.format(os.getcwd(), self._boot_iso_path)

            if self._logdir:
                if not os.path.exists(self._logdir):
                    os.makedirs(self._logdir)
            else:
                self._logdir = '.'

            other_bmcs = []
            first_controller = None
            for hw in sorted(self._uc['hosts']):
                logging.info('HW node name is %s', hw)

                if not first_controller:
                    if 'controller' in self._uc['hosts'][hw]['service_profiles'] or \
                    'caas_master' in self._uc['hosts'][hw]['service_profiles']:
                        first_controller = hw
                        logging.info('HW is first controller')

                host = self._uc['hosts'][hw]['hwmgmt']['address']
                user = self._uc['hosts'][hw]['hwmgmt']['user']
                passwd = self._uc['hosts'][hw]['hwmgmt']['password']

                bmc_log_path = '{}/{}.log'.format(self._logdir, hw)

                try:
                    hw_data = hw_detect.get_hw_data(host, user, passwd, False)
                except HWException as e:
                    error = "Harware not detected for {}: {}".format(hw, str(e))
                    logging.error(error)
                    raise BMCException(error)

                logging.info("Hardware belongs to %s product family", (hw_data['product_family']))
                if 'Unknown' in hw_data['product_family']:
                    error = "Hardware not detected for %s" % hw
                    logging.error(error)
                    raise BMCException(error)

                bmc_mod_name = 'remoteinstaller.installer.bmc_management.{}'.format(hw_data['product_family'].lower())
                bmc_mod = importlib.import_module(bmc_mod_name)
                bmc_class = getattr(bmc_mod, hw_data['product_family'])
                bmc = bmc_class(host, user, passwd, bmc_log_path)
                bmc.set_host_name(hw)

                bmc.setup_sol()

                if hw != first_controller:
                    other_bmcs.append(bmc)
                    bmc.power('off')
                else:
                    self._first_controller_bmc = bmc

            logging.debug('First controller: %s', first_controller)

            if not self._disable_bmc_initial_reset:
                self._first_controller_bmc.reset()
                time_after_reset = int(time.time())

            if not self._disable_other_bmc_reset:
                for bmc in other_bmcs:
                    bmc.reset()

            if not self._disable_bmc_initial_reset:
                # Make sure we sleep at least 6min after the first controller BMC reset
                sleep_time = 6*60-int(time.time())-time_after_reset
                if sleep_time > 0:
                    logging.debug('Waiting for first controller BMC to stabilize \
                                   (%s sec) after reset', sleep_time)
                    time.sleep(sleep_time)

            config_file_names = self._create_cloud_config(first_controller)

            self._first_controller_bmc.setup_boot_options_for_virtual_media()

            self._attach_iso_as_virtual_media(config_file_names)

            self._first_controller_bmc.boot_from_virtual_media()

            self._first_controller_bmc.wait_for_bootup()

            self._first_controller_bmc.close()

            access_info = {'vip': self._vip,
                           'installer_node_ip': self._first_controller_ip,
                           'admin_user': self._uc['users']['admin_user_name']}

            return access_info
        except BMCException as ex:
            logging.error('Installation failed: %s', str(ex))
            raise InstallException(str(ex))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-y', '--yaml', required=True,
                        help='User config yaml file path')
    parser.add_argument('-b', '--boot-iso', required=True,
                        help='Path to boot ISO image in NFS mount')
    parser.add_argument('-i', '--iso', required=True,
                        help='URL to ISO image')
    parser.add_argument('-d', '--debug', action='store_true', required=False,
                        help='Debug level for logging')
    parser.add_argument('-l', '--logdir', required=False,
                        help='Directory path for log files')
    parser.add_argument('-c', '--callback-url', required=True,
                        help='Callback URL for progress reporting')
    parser.add_argument('-K', '--client-key', required=True,
                        help='Client key file path')
    parser.add_argument('-C', '--client-cert', required=True,
                        help='Client cert file path')
    parser.add_argument('-A', '--ca-cert', required=True,
                        help='CA cert file path')
    parser.add_argument('-H', '--host-ip', required=True,
                        help='IP for hosting HTTPD and NFS')
    parser.add_argument('-T', '--http-port', required=False,
                        help='Port for HTTPD')

    parsed_args = parser.parse_args()

    if parsed_args.debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    logging.basicConfig(stream=sys.stdout, level=log_level)

    logging.debug('args: %s', parsed_args)
    installer = Installer(parsed_args)

    installer.install()

if __name__ == "__main__":
    sys.exit(main())
