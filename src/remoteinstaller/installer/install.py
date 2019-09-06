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
import distutils.util

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
    SSH_OPTS = ('-o StrictHostKeyChecking=no '
                '-o UserKnownHostsFile=/dev/null '
                '-o ServerAliveInterval=60')

    def __init__(self, callback_server, callback_uuid, yaml, logdir, args=None):
        self._callback_server = callback_server
        self._callback_uuid = callback_uuid
        self._yaml_path = yaml
        self._uc = self._read_user_config(self._yaml_path)
        self._logdir = logdir

        self._boot_iso_path = None
        self._iso_url = None
        self._callback_url = None
        self._client_key = None
        self._client_cert = None
        self._ca_cert = None
        self._own_ip = None
        self._tag = None
        self._disable_bmc_initial_reset = False
        self._disable_other_bmc_reset = True

        if args:
            self._set_arguments(args)

        self._vip = None
        self._first_controller = None
        self._first_controller_ip = None
        self._first_controller_bmc = None

        self._define_first_controller()

    def _get_bool_arg(self, args, arg, default):
        if hasattr(args, arg):
            arg_value = vars(args)[arg]
            if not isinstance(arg_value, bool):
                if isinstance(arg_value, basestring):
                    try:
                        arg_value = bool(distutils.util.strtobool(arg_value))
                        return arg_value
                    except ValueError:
                        logging.warning('Invalid value for %s: %s', arg, arg_value)
            else:
                return arg_value

        return default

    def _set_arguments(self, args):
        self._disable_bmc_initial_reset = self._get_bool_arg(args, 'disable_bmc_initial_reset', self._disable_bmc_initial_reset)
        self._disable_other_bmc_reset = self._get_bool_arg(args, 'disable_other_bmc_reset', self._disable_other_bmc_reset)

        self._boot_iso_path = args.boot_iso
        self._iso_url = args.iso
        self._callback_url = args.callback_url
        self._client_key = args.client_key
        self._client_cert = args.client_cert
        self._ca_cert = args.ca_cert
        self._own_ip = args.host_ip
        self._tag = args.tag

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

    def _setup_bmc_for_node(self, hw):
        bmc_log_path = '{}/{}.log'.format(self._logdir, hw)

        host = self._uc['hosts'][hw]['hwmgmt']['address']
        user = self._uc['hosts'][hw]['hwmgmt']['user']
        passwd = self._uc['hosts'][hw]['hwmgmt']['password']
        priv_level = self._uc['hosts'][hw]['hwmgmt'].get('priv_level', 'ADMINISTRATOR')

        try:
            hw_data = hw_detect.get_hw_data(host, user, passwd, priv_level, False)
        except HWException as e:
            error = "Hardware not detected for {}: {}".format(hw, str(e))
            logging.error(error)
            raise BMCException(error)

        logging.debug("Hardware belongs to %s product family", (hw_data['product_family']))
        if 'Unknown' in hw_data['product_family']:
            error = "Hardware not detected for %s" % hw
            logging.error(error)
            raise BMCException(error)

        bmc_mod_name = 'remoteinstaller.installer.bmc_management.{}'.format(hw_data['product_family'].lower())
        bmc_mod = importlib.import_module(bmc_mod_name)
        bmc_class = getattr(bmc_mod, hw_data['product_family'])
        bmc = bmc_class(host, user, passwd, priv_level, bmc_log_path)
        bmc.set_host_name(hw)

        return bmc

    def _define_first_controller(self):
        for hw in sorted(self._uc['hosts']):
            logging.debug('HW node name is %s', hw)

            if 'controller' in self._uc['hosts'][hw]['service_profiles'] or \
            'caas_master' in self._uc['hosts'][hw]['service_profiles']:
                self._first_controller = hw
                break

        logging.info('First controller is %s', self._first_controller)
        self._first_controller_bmc = self._setup_bmc_for_node(self._first_controller)

        domain = self._uc['hosts'][self._first_controller].get('network_domain')
        extnet = self._uc['networking']['infra_external']['network_domains'][domain]

        first_ip = extnet['ip_range_start']
        self._vip = str(IPAddress(first_ip))

        pre_allocated_ips = self._uc['hosts'][self._first_controller].get('pre_allocated_ips', None)
        if pre_allocated_ips:
            pre_allocated_infra_external_ip = pre_allocated_ips.get('infra_external', None)
            if pre_allocated_infra_external_ip:
                self._first_controller_ip = str(IPAddress(pre_allocated_infra_external_ip))

        if not self._first_controller_ip:
            self._first_controller_ip = str(IPAddress(first_ip)+1)

    def _create_cloud_config(self):
        logging.info('Create network config file')

        domain = self._uc['hosts'][self._first_controller].get('network_domain')
        extnet = self._uc['networking']['infra_external']['network_domains'][domain]

        vlan = extnet.get('vlan')
        gateway = extnet['gateway']
        dns = self._uc['networking']['dns'][0]
        cidr = extnet['cidr']
        prefix = IPNetwork(cidr).prefixlen

        controller_network_profile = self._uc['hosts'][self._first_controller]['network_profiles'][0]
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

        network_config_filename = '{}/network_config'.format(self._logdir)
        with open(network_config_filename, 'w') as f:
            if vlan:
                f.write('VLAN={}\n'.format(vlan))
            f.write('DEV={}\n'.format(device))
            f.write('IP={}/{}\n'.format(self._first_controller_ip, prefix))
            f.write('DGW={}\n'.format(gateway))
            f.write('NAMESERVER={}\n'.format(dns))
            f.write('\n')
            f.write('ISO_URL="{}"'.format(self._iso_url))

        return network_config_filename

    def _create_callback_file(self):
        logging.debug('CALLBACK_URL="%s"', self._callback_url)

        callback_url_filename = '{}/callback_url'.format(self._logdir)
        with open(callback_url_filename, 'w') as f:
            f.write(self._callback_url)

        return callback_url_filename

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
                                                                      to_file), 'put file')

    def _get_file(self, ip, user, passwd, file_name, recursive=False):
        if recursive:
            self._execute_shell('sshpass -p {} scp {} -r {}@{}:{} {}'.format(passwd,
                                                                             Installer.SSH_OPTS,
                                                                             user,
                                                                             ip,
                                                                             file_name,
                                                                             self._logdir), 'get files')
        else:
            self._execute_shell('sshpass -p {} scp {} {}@{}:{} {}'.format(passwd,
                                                                          Installer.SSH_OPTS,
                                                                          user,
                                                                          ip,
                                                                          file_name,
                                                                          self._logdir), 'get file')

    def _run_node_command(self, ip, user, passwd, command):
        self._execute_shell('sshpass -p {} ssh {} {}@{} {}'.format(passwd,
                                                                   Installer.SSH_OPTS,
                                                                   user,
                                                                   ip,
                                                                   command), 'run command: {}'.format(command))

    def _get_node_logs(self, ip, user, passwd):
        self._get_file(ip, user, passwd, '/srv/deployment/log/cm.log')
        self._get_file(ip, user, passwd, '/srv/deployment/log/bootstrap.log')
        self._get_file(ip, user, passwd, '/var/log/ironic', recursive=True)

    def _create_hosts_file(self, file_name):
        with open(file_name, 'w') as hosts_file:
            for host in self._uc['hosts'].keys():
                hosts_file.write('{}\n'.format(host))

    def _get_journal_logs(self, ip, user, passwd):
        hosts_file_name = 'host_names'
        hosts_file_path = '{}/{}'.format(self._logdir, hosts_file_name)
        self._create_hosts_file(hosts_file_name)

        host_list = ' '.join(self._uc['hosts'].keys())

        self._put_file(ip, user, passwd, hosts_file_name)
        self._put_file(ip, user, passwd, '/opt/scripts/get_journals.sh')

        self._run_node_command(ip, user, passwd, 'sh ./get_journals.sh {}'.format(hosts_file_name))

        self._get_file(ip, user, passwd, '/tmp/node_journals.tgz')

    def _get_logs_from_console(self, bmc, admin_user, admin_passwd):
        bmc_host = bmc.get_host()
        bmc_user = bmc.get_user()
        bmc_passwd = bmc.get_passwd()
        bmc_priv_level = bmc.get_priv_level()
        
        log_file = '{}/cat_bootstrap.log'.format(self._logdir)
        try:
            cat_file = CatFile(bmc_host, bmc_user, bmc_passwd, bmc_priv_level, admin_user, admin_passwd)
            cat_file.cat('/srv/deployment/log/bootstrap.log', log_file)
        except CatFileException as ex:
            logging.info('Could not cat file from console: %s', str(ex))

            cat_file = CatFile(bmc_host, bmc_user, bmc_passwd, bmc_priv_level, 'root', 'root')
            cat_file.cat('/srv/deployment/log/bootstrap.log', log_file)

    def get_logs(self, admin_passwd):
        admin_user = self._uc['users']['admin_user_name']

        ssh_check_command = 'nc -w1 {} 22 </dev/null &> /dev/null'.format(self._first_controller_ip)
        ssh_check_fails = os.system(ssh_check_command)

        if not ssh_check_fails:
            self._get_node_logs(self._first_controller_ip, admin_user, admin_passwd)

            self._get_journal_logs(self._first_controller_ip, admin_user, admin_passwd)
        else:
            self._get_logs_from_console(self._first_controller_bmc,
                                        admin_user,
                                        admin_passwd)

    def _setup_bmcs(self):
        other_bmcs = []
        for hw in sorted(self._uc['hosts']):
            logging.info('HW node name is %s', hw)

            bmc = self._setup_bmc_for_node(hw)
            bmc.setup_sol()

            if hw != self._first_controller:
                other_bmcs.append(bmc)
                bmc.power('off')

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

    def get_access_info(self):
        access_info = {'vip': self._vip,
                       'installer_node_ip': self._first_controller_ip,
                       'admin_user': self._uc['users']['admin_user_name']}

        return access_info

    def _set_progress(self, description, failed=False):
        if failed:
            state = 'failed'
        else:
            state = 'ongoing'

        self._callback_server.set_state(self._callback_uuid, state, description)

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

            self._set_progress('Setup BMCs')
            self._setup_bmcs()

            self._set_progress('Create config files')
            network_config_filename = self._create_cloud_config()
            callback_url_filename = self._create_callback_file()

            patch_files = [self._yaml_path,
                           network_config_filename,
                           callback_url_filename]

            if self._client_cert:
                patch_files.append(self._client_cert)
            if self._client_key:
                patch_files.append(self._client_key)
            if self._ca_cert:
                patch_files.append(self._ca_cert)

            self._set_progress('Setup boot options for virtual media')
            self._first_controller_bmc.setup_boot_options_for_virtual_media()

            self._set_progress('Attach iso as virtual media')
            self._attach_iso_as_virtual_media(patch_files)

            self._set_progress('Boot from virtual media')
            self._first_controller_bmc.boot_from_virtual_media()

            self._set_progress('Wait for bootup')
            self._first_controller_bmc.wait_for_bootup()

            self._set_progress('Wait deployment start')

            self._first_controller_bmc.close()
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
    parser.add_argument('-l', '--logdir', required=True,
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
    installer = Installer(parsed_args.yaml, parsed_args.logdir, parsed_args)

    installer.install()

if __name__ == "__main__":
    sys.exit(main())
