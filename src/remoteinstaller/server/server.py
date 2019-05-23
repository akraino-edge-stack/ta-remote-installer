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
from configparser import ConfigParser
import logging
from logging.handlers import RotatingFileHandler
import os
from threading import Thread
import time
import json
import urllib
import urlparse
import uuid as uuid_module
import ssl

from wsgiref.simple_server import make_server
import routes

from remoteinstaller.installer.install import Installer
from remoteinstaller.installer.install import InstallException


class LoggingSSLSocket(ssl.SSLSocket):
    def accept(self, *args, **kwargs):
        try:
            result = super(LoggingSSLSocket, self).accept(*args, **kwargs)
        except Exception as ex:
            logging.warning('SSLSocket.accept raised exception: %s', str(ex))
            raise
        return result


class InstallationWorker(Thread):
    def __init__(self, server, uuid, admin_passwd, yaml, logdir, args=None):
        super(InstallationWorker, self).__init__(name=uuid)
        self._server = server
        self._uuid = uuid
        self._admin_passwd = admin_passwd
        self._yaml = yaml
        self._logdir = logdir
        self._args = args

    def run(self):
        installer = Installer(self._server, self._uuid, self._yaml, self._logdir, self._args)
        access_info = installer.get_access_info()

        if self._args:
            try:
                installer.install()
                logging.info('Installation triggered for %s', self._uuid)
            except InstallException as ex:
                logging.warning('Installation triggering failed for %s: %s', self._uuid, str(ex))
                self._server.set_state(self._uuid, 'failed', str(ex))
                return

        installation_finished = False
        while not installation_finished:
            state = self._server.get_state(self._uuid)
            if not state['status'] == 'ongoing':
                installation_finished = True
            else:
                logging.info('Installation of %s still ongoing (%s%%): %s',
                             self._uuid,
                             state['percentage'],
                             state['description'])
                time.sleep(10)

        logging.info('Installation finished for %s: %s', self._uuid, state)
        logging.info('Login details for installation %s: %s', self._uuid, str(access_info))

        logging.info('Getting logs for installation %s...', self._uuid)
        installer.get_logs(self._admin_passwd)
        logging.info('Logs retrieved for %s', self._uuid)

class Server(object):
    DEFAULT_PATH = '/opt/remoteinstaller'
    USER_CONFIG_PATH = 'user-configs'
    ISO_PATH = 'images'
    CERTIFICATE_PATH = 'certificates'
    INSTALLATIONS_PATH = 'installations'
    USER_CONFIG_NAME = 'user_config.yaml'
    EXTRA_CONFIG_NAME = 'installation.ini'

    def __init__(self,
                 host,
                 port,
                 cert=None,
                 key=None,
                 client_cert=None,
                 client_key=None,
                 ca_cert=None,
                 path=None,
                 http_port=None):
        self._host = host
        self._port = port
        self._http_port = http_port

        self._path = path
        if not self._path:
            self._path = Server.DEFAULT_PATH

        self._cert = '{}/{}/{}'.format(self._path, Server.CERTIFICATE_PATH, cert)
        self._key = '{}/{}/{}'.format(self._path, Server.CERTIFICATE_PATH, key)
        self._client_cert = '{}/{}/{}'.format(self._path, Server.CERTIFICATE_PATH, client_cert)
        self._client_key = '{}/{}/{}'.format(self._path, Server.CERTIFICATE_PATH, client_key)
        self._ca_cert = '{}/{}/{}'.format(self._path, Server.CERTIFICATE_PATH, ca_cert)

        self._ongoing_installations = {}
        self._load_states()

    def get_server_keys(self):
        return {'cert': self._cert, 'key': self._key, 'ca_cert': self._ca_cert}

    def _read_admin_passwd(self, cloud_name):
        with open('{}/{}/{}/admin_passwd'.format(self._path,
                                                 Server.USER_CONFIG_PATH,
                                                 cloud_name)) as pwf:
            admin_passwd = pwf.readline().strip()

        return admin_passwd

    def _get_yaml_path_for_cloud(self, cloud_name):
        yaml = '{}/{}/{}/{}'.format(self._path,
                                    Server.USER_CONFIG_PATH,
                                    cloud_name,
                                    Server.USER_CONFIG_NAME)
        if not os.path.isfile(yaml):
            raise ServerError('YAML file {} not found'.format(yaml))

        return yaml

    def _load_states(self):
        uuid_list = os.listdir('{}/{}'.format(self._path, Server.INSTALLATIONS_PATH))
        for uuid in uuid_list:
            state_file_name = '{}/{}/{}.state'.format(self._path, Server.INSTALLATIONS_PATH, uuid)
            if os.path.exists(state_file_name):
                with open(state_file_name) as sf:
                    state_json = sf.readline()
                    self._ongoing_installations[uuid] = json.loads(state_json)

                if self._ongoing_installations[uuid]['status'] == 'ongoing':
                    logdir = '{}/{}/{}'.format(self._path, Server.INSTALLATIONS_PATH, uuid)
                    cloud_name = self._ongoing_installations[uuid]['cloud_name']
                    admin_passwd = self._read_admin_passwd(cloud_name)
                    yaml = self._get_yaml_path_for_cloud(cloud_name)
                    worker = InstallationWorker(self, uuid, admin_passwd, yaml, logdir)
                    worker.start()

    def _set_state(self, uuid, status, description, percentage=None, cloud_name=None):
        if not self._ongoing_installations.get(uuid, None):
            self._ongoing_installations[uuid] = {}
        self._ongoing_installations[uuid]['status'] = status
        self._ongoing_installations[uuid]['description'] = description
        if percentage is not None:
            self._ongoing_installations[uuid]['percentage'] = percentage
        if cloud_name:
            self._ongoing_installations[uuid]['cloud_name'] = cloud_name

        state_file = '{}/{}/{}.state'.format(self._path, Server.INSTALLATIONS_PATH, uuid)
        with open(state_file, 'w') as sf:
            sf.write(json.dumps(self._ongoing_installations[uuid]))

    def set_state(self, uuid, status, description, percentage=None):
        logging.debug('set_state called for %s: status=%s, description=%s, percentage=%s',
                      uuid, status, description, percentage)

        if not uuid in self._ongoing_installations:
            raise ServerError('Installation id {} not found'.format(uuid))

        if not status in ['ongoing', 'failed', 'completed']:
            raise ServerError('Invalid state: {}'.format(status))

        self._set_state(uuid, status, description, percentage)

    def get_state(self, uuid):
        logging.debug('get_state called for %s', uuid)

        if not uuid in self._ongoing_installations:
            raise ServerError('Installation id {} not found'.format(uuid))

        return {'status': self._ongoing_installations[uuid]['status'],
                'description': self._ongoing_installations[uuid]['description'],
                'percentage': self._ongoing_installations[uuid]['percentage']}

    def _read_extra_args(self, cloud_name):
        extra = {}

        extra_config_filename = '{}/{}/{}/{}'.format(self._path,
                                    Server.USER_CONFIG_PATH,
                                    cloud_name,
                                    Server.EXTRA_CONFIG_NAME)

        if os.path.isfile(extra_config_filename):
            logging.debug('Read extra installation args from: %s', extra_config_filename)
            extra_config = ConfigParser()
            with open(extra_config_filename, 'r') as extra_config_file:
                extra_config.readfp(extra_config_file)

            if extra_config.has_section('extra'):
                for key, value in extra_config.items('extra'):
                    extra[key] = value

        return extra

    def start_installation(self, cloud_name, iso, boot_iso):
        logging.debug('start_installation called with args: (%s, %s, %s)', cloud_name, iso, boot_iso)

        uuid = str(uuid_module.uuid4())[:8]

        args = argparse.Namespace()

        extra_args = self._read_extra_args(cloud_name)
        vars(args).update(extra_args)

        args.yaml = self._get_yaml_path_for_cloud(cloud_name)

        iso_path = '{}/{}/{}'.format(self._path, Server.ISO_PATH, iso)
        if not os.path.isfile(iso_path):
            raise ServerError('ISO file {} not found'.format(iso_path))

        boot_iso_path = '{}/{}/{}'.format(self._path, Server.ISO_PATH, boot_iso)
        if not os.path.isfile(boot_iso_path):
            raise ServerError('Provisioning ISO file {} not found'.format(boot_iso_path))

        http_port_part = ''
        if self._http_port:
            http_port_part = ':{}'.format(self._http_port)

        args.iso = 'https://{}{}/{}/{}'.format(self._host, http_port_part, Server.ISO_PATH, iso)

        args.logdir = '{}/{}/{}'.format(self._path, Server.INSTALLATIONS_PATH, uuid)

        os.makedirs(args.logdir)

        args.boot_iso = '{}/{}/{}'.format(self._path, Server.ISO_PATH, boot_iso)

        args.tag = uuid
        args.callback_url = 'https://{}:{}/v1/installations/{}/state'.format(self._host,
                                                                             self._port,
                                                                             uuid)

        args.client_cert = self._client_cert
        args.client_key = self._client_key
        args.ca_cert = self._ca_cert
        args.host_ip = self._host

        self._set_state(uuid, 'ongoing', '', 0, cloud_name)

        admin_passwd = self._read_admin_passwd(cloud_name)
        worker = InstallationWorker(self, uuid, admin_passwd, args.yaml, args.logdir, args)
        worker.start()

        return uuid


class ServerError(Exception):
    pass


class HTTPErrors(object):
    # response for a successful GET, PUT, PATCH, DELETE,
    # can also be used for POST that does not result in creation.
    HTTP_OK = 200
    # response to a POST which results in creation.
    HTTP_CREATED = 201
    # response to a successfull request that won't be returning any body like a DELETE request
    HTTP_NO_CONTENT = 204
    # used when http caching headers are in play
    HTTP_NOT_MODIFIED = 304
    # the request is malformed such as if the body does not parse
    HTTP_BAD_REQUEST = 400
    # when no or invalid authentication details are provided.
    # also useful to trigger an auth popup API is used from a browser
    HTTP_UNAUTHORIZED_OPERATION = 401
    # when authentication succeeded but authenticated user doesn't have access to the resource
    HTTP_FORBIDDEN = 403
    # when a non-existent resource is requested
    HTTP_NOT_FOUND = 404
    # when an http method is being requested that isn't allowed for the authenticated user
    HTTP_METHOD_NOT_ALLOWED = 405
    # indicates the resource at this point is no longer available
    HTTP_GONE = 410
    # if incorrect content type was provided as part of the request
    HTTP_UNSUPPORTED_MEDIA_TYPE = 415
    # used for validation errors
    HTTP_UNPROCESSABLE_ENTITY = 422
    # when request is rejected due to rate limiting
    HTTP_TOO_MANY_REQUESTS = 429
    # Other errrors
    HTTP_INTERNAL_ERROR = 500

    @staticmethod
    def get_ok_status():
        return '%d OK' % HTTPErrors.HTTP_OK

    @staticmethod
    def get_object_created_successfully_status():
        return '%d Created' % HTTPErrors.HTTP_CREATED

    @staticmethod
    def get_request_not_ok_status():
        return '%d Bad request' % HTTPErrors.HTTP_BAD_REQUEST

    @staticmethod
    def get_resource_not_found_status():
        return '%d Not found' % HTTPErrors.HTTP_NOT_FOUND

    @staticmethod
    def get_unsupported_content_type_status():
        return '%d Unsupported content type' % HTTPErrors.HTTP_UNSUPPORTED_MEDIA_TYPE

    @staticmethod
    def get_validation_error_status():
        return '%d Validation error' % HTTPErrors.HTTP_UNPROCESSABLE_ENTITY

    @staticmethod
    def get_internal_error_status():
        return '%d Internal error' % HTTPErrors.HTTP_INTERNAL_ERROR


class HTTPRPC(object):
    def __init__(self):
        self.req_body = ''
        self.req_filter = ''
        self.req_params = {}
        self.req_method = ''
        self.req_content_type = ''
        self.req_content_size = 0
        self.req_path = ''

        self.rep_body = ''
        self.rep_status = ''

    def __str__(self):
        return str.format('REQ: body:{body} filter:{filter} '
                          'params:{params} method:{method} path:{path} '
                          'content_type:{content_type} content_size:{content_size} '
                          'REP: body:{rep_body} status:{status}',
                          body=self.req_body, filter=self.req_filter,
                          params=str(self.req_params), method=self.req_method, path=self.req_path,
                          content_type=self.req_content_type, content_size=self.req_content_size,
                          rep_body=self.rep_body, status=self.rep_status)

class WSGIHandler(object):
    def __init__(self, server):
        logging.debug('WSGIHandler constructor called')

        self.server = server

        self.mapper = routes.Mapper()
        self.mapper.connect(None, '/apis', action='get_apis')
        self.mapper.connect(None, '/{api}/installations', action='handle_installations')
        self.mapper.connect(None, '/{api}/installations/{uuid}/state', action='handle_state')

    def handle_installations(self, rpc):
        if rpc.req_method == 'POST':
            self._start_installation(rpc)
        else:
            rpc.rep_status = HTTPErrors.get_request_not_ok_status()
            rpc.rep_status += ', only POST are possible to this resource'

    def handle_state(self, rpc):
        if rpc.req_method == 'GET':
            self._get_state(rpc)
        elif rpc.req_method == 'POST':
            self._set_state(rpc)
        else:
            rpc.rep_status = HTTPErrors.get_request_not_ok_status()
            rpc.rep_status += ', only GET/POST are possible to this resource'

    def _start_installation(self, rpc):
        """
            Request: POST http://<ip:port>/v1/installations
                {
                    'cloud-name': <name of the cloud>,
                    'iso': <iso image name>,
                    'provisioning-iso': <boot iso image name>
                }
            Response: http status set correctly
                {
                    'uuid': <operation identifier>
                }
        """

        logging.debug('_start_installation called')
        try:
            if not rpc.req_body:
                rpc.rep_status = HTTPErrors.get_request_not_ok_status()
            else:
                request = json.loads(rpc.req_body)
                cloud_name = request['cloud-name']
                iso = request['iso']
                boot_iso = request['provisioning-iso']

                uuid = self.server.start_installation(cloud_name, iso, boot_iso)

                rpc.rep_status = HTTPErrors.get_ok_status()
                reply = {'uuid': uuid}
                rpc.rep_body = json.dumps(reply)
        except KeyError as ex:
            raise ServerError('Missing request parameter: {}'.format(str(ex)))
        except Exception as exp:  # pylint: disable=broad-except
            rpc.rep_status = HTTPErrors.get_internal_error_status()
            rpc.rep_status += ','
            rpc.rep_status += str(exp)

    def _get_state(self, rpc):
        """
            Request: GET http://<ip:port>/v1/installations/<uuid>/state
                {
                }
            Response: http status set correctly
                {
                    'status': <ongoing|completed|failed>,
                    'description': <description about the progress>,
                    'percentage': <percentage completed of the installation>
                }
        """

        logging.debug('_get_state called')
        try:
            uuid = rpc.req_params['uuid']

            reply = self.server.get_state(uuid)

            rpc.rep_status = HTTPErrors.get_ok_status()
            rpc.rep_body = json.dumps(reply)
        except KeyError as ex:
            raise ServerError('Missing request parameter: {}'.format(str(ex)))
        except Exception as exp:  # pylint: disable=broad-except
            rpc.rep_status = HTTPErrors.get_internal_error_status()
            rpc.rep_status += ','
            rpc.rep_status += str(exp)

    def _set_state(self, rpc):
        """
            Request: POST http://<ip:port>/v1/installations/<uuid>/state
                {
                    'status': <ongoing|completed|failed>,
                    'description': <description about the progress>,
                    'percentage': <percentage completed of the installation>
                }
            Response: http status set correctly
                {
                }
        """

        logging.debug('_set_state called')
        try:
            if not rpc.req_body:
                rpc.rep_status = HTTPErrors.get_request_not_ok_status()
            else:
                request = json.loads(rpc.req_body)
                uuid = rpc.req_params['uuid']
                status = request['status']
                description = request['description']
                percentage = request.get('percentage', None)

                self.server.set_state(uuid, status, description, percentage)

                rpc.rep_status = HTTPErrors.get_ok_status()
                reply = {}
                rpc.rep_body = json.dumps(reply)
        except KeyError as ex:
            rpc.rep_status = HTTPErrors.get_request_not_ok_status()
            raise ServerError('Missing request parameter: {}'.format(str(ex)))
        except Exception as exp:  # pylint: disable=broad-except
            rpc.rep_status = HTTPErrors.get_internal_error_status()
            rpc.rep_status += ','
            rpc.rep_status += str(exp)

    def _read_header(self, rpc, environ):
        rpc.req_method = environ['REQUEST_METHOD']
        rpc.req_path = environ['PATH_INFO']
        try:
            rpc.req_filter = urlparse.parse_qs(urllib.unquote(environ['QUERY_STRING']))
        except KeyError:
            rpc.req_filter = {}
        rpc.req_content_type = environ['CONTENT_TYPE']
        try:
            content_len = environ['CONTENT_LENGTH']
            if not content_len:
                rpc.req_content_size = 0
            else:
                rpc.req_content_size = int(content_len)
        except KeyError:
            rpc.req_content_size = 0

    def _get_action(self, rpc):
        # get the action to be done
        action = ''
        match_result = self.mapper.match(rpc.req_path)
        if not match_result:
            rpc.rep_status = HTTPErrors.get_resource_not_found_status()
            raise ServerError('URL does not match')

        resultdict = {}
        if isinstance(match_result, dict):
            resultdict = match_result
        else:
            resultdict = match_result[0]

        try:
            action = resultdict['action']
            for key, value in resultdict.iteritems():
                if key != 'action':
                    rpc.req_params[key] = value
        except KeyError:
            rpc.rep_status = HTTPErrors.get_internal_error_status()
            raise ServerError('No action found')

        return action

    def _read_body(self, rpc, environ):
        # get the body if available
        if rpc.req_content_size:
            if rpc.req_content_type == 'application/json':
                rpc.req_body = environ['wsgi.input'].read(rpc.req_content_size)
            else:
                rpc.rep_status = HTTPErrors.get_unsupported_content_type_status()
                raise ServerError('Content type is not json')

    def __call__(self, environ, start_response):
        logging.debug('Handling request started, environ=%s', str(environ))

        # For request and resonse data
        rpc = HTTPRPC()
        rpc.rep_status = HTTPErrors.get_ok_status()

        try:
            self._read_header(rpc, environ)

            action = self._get_action(rpc)

            self._read_body(rpc, environ)

            logging.debug('Calling %s with rpc=%s', action, str(rpc))
            actionfunc = getattr(self, action)
            actionfunc(rpc)
        except ServerError as ex:
            rpc.rep_status = HTTPErrors.get_request_not_ok_status()
            rpc.rep_status += ', '
            rpc.rep_status += str(ex)
        except AttributeError:
            rpc.rep_status = HTTPErrors.get_internal_error_status()
            rpc.rep_status += ','
            rpc.rep_status += 'Missing action function'
        except Exception as exp:  # pylint: disable=broad-except
            rpc.rep_status = HTTPErrors.get_internal_error_status()
            rpc.rep_status += ', '
            rpc.rep_status += str(exp)

        logging.debug('Replying with rpc=%s', str(rpc))
        response_headers = [('Content-type', 'application/json')]
        start_response(rpc.rep_status, response_headers)
        return [rpc.rep_body]

def wrap_socket(sock, keyfile=None, certfile=None,
                server_side=False, cert_reqs=ssl.CERT_NONE,
                ssl_version=ssl.PROTOCOL_SSLv23, ca_certs=None,
                do_handshake_on_connect=True,
                suppress_ragged_eofs=True,
                ciphers=None):

    return LoggingSSLSocket(sock=sock, keyfile=keyfile, certfile=certfile,
                            server_side=server_side, cert_reqs=cert_reqs,
                            ssl_version=ssl_version, ca_certs=ca_certs,
                            do_handshake_on_connect=do_handshake_on_connect,
                            suppress_ragged_eofs=suppress_ragged_eofs,
                            ciphers=ciphers)

def main():
    parser = argparse.ArgumentParser()
    parser = argparse.ArgumentParser()
    parser.add_argument('-H', '--host', required=True, metavar='<bind ip>', help='binding ip of the server')
    parser.add_argument('-P', '--listen', required=True, metavar='<bind port>', help='binding port of the server')
    parser.add_argument('-S', '--server', required=False, metavar='<external ip>', help='externally visible ip of the server')
    parser.add_argument('-B', '--port', required=False, metavar='<external port>', help='externally visible port of the server')
    parser.add_argument('-C', '--cert', required=False, metavar='<server cert file>', help='path to server cert file')
    parser.add_argument('-K', '--key', required=False, metavar='<server key file>', help='path to server private key file')
    parser.add_argument('-c', '--client-cert', required=False, metavar='<client cert file>', help='path to client cert file')
    parser.add_argument('-k', '--client-key', required=False, metavar='<client key file>', help='path to client key file')
    parser.add_argument('-A', '--ca-cert', required=False, metavar='<CA cert file>', help='path to CA cert file')
    parser.add_argument('-p', '--path', required=False, metavar='<path to installer files>', help='path to remote installer files')
    parser.add_argument('-T', '--http-port', required=False, metavar='<HTTPD port>', help='port for HTTPD')
    parser.add_argument('-d', '--debug', required=False, help='set debug level for logging',
                        action='store_true')
    parser.add_argument('--log-file', required=False, default='/var/log/remote-installer.log', metavar='<server log file>', help='path to server log file')
    parser.add_argument('--log-file-max-size', type=int, default=5, required=False, metavar='<max size>', help='server log file max size in MB')
    parser.add_argument('--log-file-max-count', type=int, default=10, required=False, metavar='<max count>', help='server log file count')

    args = parser.parse_args()

    if args.debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    logformat = '%(asctime)s %(threadName)s:%(levelname)s %(message)s'
    logging.basicConfig(stream=sys.stdout, level=log_level, format=logformat)

    log_file_handler = RotatingFileHandler(args.log_file,
                                           maxBytes=(args.log_file_max_size*1024*1024),
                                           backupCount=args.log_file_max_count)
    log_file_handler.setFormatter(logging.Formatter(logformat))
    log_file_handler.setLevel(log_level)
    logging.getLogger().addHandler(log_file_handler)

    logging.info('remote-installer started')
    logging.debug('remote-installer args: %s', args)

    host = args.server
    if not host:
        host = args.host

    port = args.port
    if not port:
        port = args.listen

    server = Server(host, port, args.cert, args.key, args.client_cert, args.client_key, args.ca_cert, args.path, args.http_port)

    wsgihandler = WSGIHandler(server)

    wsgi_server = make_server(args.host, int(args.listen), wsgihandler)

    if args.cert:
        server_keys = server.get_server_keys()
        wsgi_server.socket = wrap_socket(wsgi_server.socket,
                                         certfile=server_keys['cert'],
                                         keyfile=server_keys['key'],
                                         server_side=True,
                                         ca_certs=server_keys['ca_cert'],
                                         cert_reqs=ssl.CERT_REQUIRED)

    wsgi_server.serve_forever()

if __name__ == "__main__":
    sys.exit(main())
