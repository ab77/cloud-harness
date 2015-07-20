#!/usr/bin/env python

'''
Version: 0.1
Author: Anton Belodedenko (anton@belodedenko.me)
Date: 16/06/2015
Name: Cloud Harness
Git: https://github.com/ab77/cloud-harness

Synopsis:
Python wrapper for cloud service provider APIs/SDKs, supporting:
- Azure Service Management Module

Requires:
- [Requests: HTTP for Humans](http://docs.python-requests.org/en/latest/)
- [Python module that makes working with XML feel like you are working with JSON](https://github.com/martinblech/xmltodict)
- [Microsoft Azure Python SDK/API](https://github.com/Azure/azure-sdk-for-python)
- [Python interface to the OpenSSL library](https://github.com/pyca/pyopenssl)
- [PyCrypto - The Python Cryptography Toolkit](https://www.dlitz.net/software/pycrypto/)
'''

import time, sys, os, argparse, logging, json, pprint, ConfigParser, hashlib, string, inspect, traceback

from datetime import date, timedelta, datetime
from calendar import timegm
from random import SystemRandom, randint
from xml.etree.ElementTree import Element, SubElement, tostring, fromstring
from base64 import b64encode
from urlparse import urlsplit, urlunsplit, parse_qs
from urllib import quote_plus
from functools import wraps

try:
    from requests import Session
except ImportError:
    sys.stderr.write('ERROR: Python module "requests" not found, please run "pip install requests".\n')
    sys.exit(1)

try:
    from azure import *
    from azure.servicemanagement import *
    from azure.storage import AccessPolicy, BlobService
    from azure.storage.sharedaccesssignature import SharedAccessPolicy, SharedAccessSignature
except ImportError:
    sys.stderr.write('ERROR: Python module "azure" not found, please run "pip install azure".\n')
    sys.exit(1)

try:
    import xmltodict
except ImportError:
    sys.stderr.write('ERROR: Python module "xmltodict" not found, please run "pip install xmltodict".\n')
    sys.exit()

try:
    import OpenSSL.crypto as pyopenssl
except ImportError:
    sys.stderr.write('ERROR: Python module "pyOpenSSL" not found, please run "pip install pyopenssl".\n')
    sys.exit()

try:
    from Crypto.Util import asn1
    from Crypto.PublicKey import RSA    
except ImportError:
    sys.stderr.write('ERROR: Python module "PyCrypto" not found, please run "pip install pycrypto".\n')
    sys.exit()

def mkdate(dt, format):
    return datetime.strftime(dt, format)

def recurse_dict(d):
    for k, v in d.iteritems():
        if isinstance(v, dict):
            return recurse_dict(v)
        else:
            return v

DEFAULT_TRIES = 3
DEFAULT_DELAY = 2
DEFAULT_BACKOFF = 2

def retry(ExceptionToCheck, tries=DEFAULT_TRIES, delay=DEFAULT_DELAY, backoff=DEFAULT_BACKOFF, cdata=None):
    """Retry calling the decorated function using an exponential backoff.

    http://www.saltycrane.com/blog/2009/11/trying-out-retry-decorator-python/
    original from: http://wiki.python.org/moin/PythonDecoratorLibrary#Retry

    :param ExceptionToCheck: the exception to check. may be a tuple of
        exceptions to check
    :type ExceptionToCheck: Exception or tuple
    :param tries: number of times to try (not retry) before giving up
    :type tries: int
    :param delay: initial delay between retries in seconds
    :type delay: int
    :param backoff: backoff multiplier e.g. value of 2 will double the delay
        each retry
    :type backoff: int
    :param logger: logger to use. If None, print
    :type logger: logging.Logger instance
    """
    def deco_retry(f):
        @wraps(f)
        def f_retry(*args, **kwargs):
            mtries, mdelay = tries, delay
            while mtries > 0:
                try:
                    return f(*args, **kwargs)
                except ExceptionToCheck, e:
                    logger(message='%s, retrying in %d seconds (mtries=%d): %s' % (repr(e), mdelay, mtries, str(cdata)))
                    time.sleep(mdelay)
                    mtries -= 1
                    mdelay *= backoff
            return f(*args, **kwargs)
        return f_retry  # true decorator
    return deco_retry

def args():
    parser = argparse.ArgumentParser()
    sp = parser.add_subparsers()    
    azure = sp.add_parser('azure')
    azure.add_argument('provider', action='store_const', const='azure', help=argparse.SUPPRESS)
    azure.add_argument('--action', type=str, required=False, default=AzureCloudClass.default_action, choices=[a['action'] for a in AzureCloudClass.actions], help='action (default: %s)' % AzureCloudClass.default_action)
    azure.add_argument('--subscription_id', type=str, required=False, default=AzureCloudClass.default_subscription_id, help='Azure subscription ID (default: %s)' % AzureCloudClass.default_subscription_id)
    azure.add_argument('--management_certificate', type=str, required=False, default=AzureCloudClass.default_management_certificate, help='Azure management certificate (default: %s)' % AzureCloudClass.default_management_certificate)
    azure.add_argument('--start_date', type=str, default=mkdate(AzureCloudClass.default_start_date, '%Y-%m-%d'), help='start date for list_subscription_operations (default: %s)' % mkdate(AzureCloudClass.default_start_date, '%Y-%m-%d'))
    azure.add_argument('--end_date', type=str, default=mkdate(AzureCloudClass.default_end_date, '%Y-%m-%d'), help='end date for subscription_operations (default: %s)' % mkdate(AzureCloudClass.default_end_date, '%Y-%m-%d'))
    azure.add_argument('--service', type=str, required=False, help='hosted service name')
    azure.add_argument('--account', type=str, required=False, default=BaseCloudHarnessClass.default_storage_account, help='storage account name (default: %s)' % BaseCloudHarnessClass.default_storage_account)
    azure.add_argument('--account_type', type=str, required=False, default=AzureCloudClass.default_account_type, choices=['Standard_LRS', 'Standard_ZRS', 'Standard_GRS', 'Standard_RAGRS'], help='storage account type (default %s)' % AzureCloudClass.default_account_type)
    azure.add_argument('--key_type', type=str, required=False, default=AzureCloudClass.default_key_type, choices=['Primary', 'Secondary'], help='storage account key type (default %s)' % AzureCloudClass.default_key_type)
    azure.add_argument('--container', type=str, required=False, default=BaseCloudHarnessClass.default_storage_container, help='storage container name (default: %s)' % BaseCloudHarnessClass.default_storage_container)
    azure.add_argument('--label', type=str, required=False, help='resource label')
    azure.add_argument('--description', type=str, required=False, help='resource description')
    azure.add_argument('--name', type=str, nargs='+', required=False, help='resource name(s)')
    azure.add_argument('--group', type=str, required=False, help='group name')
    azure.add_argument('--dns', type=str, nargs='+', required=False, help='dns server name(s)')
    azure.add_argument('--ipaddr', type=str, nargs='+', required=False, help='reserved IP address name or DNS server IP address(es)')
    azure.add_argument('--blob', type=str, nargs='+', required=False, help='disk image blob name(s)')
    azure.add_argument('--blobtype', type=str, required=False, default=AzureCloudClass.default_blobtype, choices=['block', 'page'], help='blob type (defualt: %s)' % AzureCloudClass.default_blobtype)
    azure.add_argument('--family', type=str, required=False, help='OS image family')
    azure.add_argument('--disk', type=str, required=False, help='disk name')
    azure.add_argument('--delete_vhds', action='store_true', required=False, help='delete VHDs')
    azure.add_argument('--delete_disks', action='store_true', required=False, help='delete disks')
    azure.add_argument('--async', action='store_true', required=False, help='asynchronous operation')
    azure.add_argument('--thumbprint', type=str, required=False, help='certificate thumbprint')
    azure.add_argument('--certificate', type=str, required=False, help='certificate file')
    azure.add_argument('--publish_settings', type=str, required=False, help='Azure publish_settings file')    
    azure.add_argument('--request_id', type=str, required=False, help='request ID')    
    azure.add_argument('--status', type=str, required=False, default=AzureCloudClass.default_status, choices=['Succeeded', 'InProgress', 'Failed'], help='wait for operation status (default %s)' % AzureCloudClass.default_status)
    azure.add_argument('--post_capture_action', type=str, required=False, default=AzureCloudClass.default_post_capture_action, choices=['Delete', 'Reprovision'], help='post capture action (default %s)' % AzureCloudClass.default_post_capture_action)
    azure.add_argument('--wait', type=int, required=False, default=AzureCloudClass.default_wait, help='operation wait time (default %i)' % AzureCloudClass.default_wait)
    azure.add_argument('--timeout', type=int, required=False, default=AzureCloudClass.default_timeout, help='operation timeout (default %i)' % AzureCloudClass.default_timeout)
    azure.add_argument('--deployment', type=str, required=False, help='(source) deployment name')
    azure.add_argument('--upgrade_domain', type=int, required=False, help='upgrade_domain')    
    azure.add_argument('--production_deployment', type=str, required=False, help='production deployment name')
    azure.add_argument('--package_url', type=str, required=False, help='service package URL')
    azure.add_argument('--package_config', type=str, required=False, help='service package configuration file')
    azure.add_argument('--deployment_status', type=str, required=False, choices=['Running', 'Suspended'], help='deployment status')
    azure.add_argument('--mode', type=str, required=False, default=AzureCloudClass.default_mode, choices=['auto', 'manual'], help='deployment rollback mode (default %s)' % AzureCloudClass.default_mode)
    azure.add_argument('--force', action='store_true', required=False, help='accept data loss during deployment rollback')
    azure.add_argument('--slot', type=str, required=False, default=AzureCloudClass.default_deployment_slot, help='deployment slot (default %s)' % AzureCloudClass.default_deployment_slot)
    azure.add_argument('--size', type=str, required=False, default=AzureCloudClass.default_size, help='VM size (default %s)' % AzureCloudClass.default_size)
    azure.add_argument('--disk_size', type=int, required=False, default=AzureCloudClass.default_disk_size, help='disk size in GB (default %s)' % AzureCloudClass.default_disk_size)
    azure.add_argument('--host_caching', type=str, required=False, default=AzureCloudClass.default_host_caching, choices=['ReadOnly', 'None', 'ReadOnly', 'ReadWrite'], help='disk caching (default %s)' % AzureCloudClass.default_host_caching)
    azure.add_argument('--username', type=str, required=False, default=AzureCloudClass.default_user_name, help='username for VM deployments (default %s)' % AzureCloudClass.default_user_name)
    azure.add_argument('--password', type=str, required=False, help='password for VM deployments')
    azure.add_argument('--pwd_expiry', type=int, required=False, default=AzureCloudClass.default_pwd_expiry, help='VMAccess password expiry (default: %i days)' % AzureCloudClass.default_pwd_expiry)
    azure.add_argument('--disable_pwd_auth', action='store_true', required=False, help='disable Linux password authentication')
    azure.add_argument('--ssh_auth', action='store_true', required=False, help='Linux SSH key authentication')
    azure.add_argument('--readonly', action='store_true', required=False, help='limit to read-only operations')
    azure.add_argument('--verbose', action='store_true', required=False, help='verbose output')
    azure.add_argument('--custom_data_file', type=str, required=False, help='custom data file')
    azure.add_argument('--algorithm', type=str, default=AzureCloudClass.default_algorithm, required=False, help='thumbprint algorithm (default %s)' % AzureCloudClass.default_algorithm)
    azure.add_argument('--os', type=str, required=False, choices=['Windows', 'Linux'], help='OS type')
    azure.add_argument('--os_state', type=str, default=AzureCloudClass.default_os_state, required=False, choices=['Generalized', 'Specialized '], help='OS image state (default: %s)' % AzureCloudClass.default_os_state)
    azure.add_argument('--language', type=str, required=False, help='OS image language')
    azure.add_argument('--availset', type=str, required=False, help='availability set name')
    azure.add_argument('--network', type=str, required=False, help='virtual network name')
    azure.add_argument('--subnet', type=str, nargs='+', required=False, help='subnet name(s) (e.g. Subnet-1, Subnet-2, Subnet-3, Subnet-4, Subnet-5)')
    azure.add_argument('--subnetaddr', type=str, nargs='+', required=False, help='subnet network address prefix(s) (e.g. 10.0.0.0/11, 10.32.0.0/11, 10.64.0.0/10, 192.168.0.0/19, 192.168.32.0/19 )')
    azure.add_argument('--vnetaddr', type=str, nargs='+', required=False, help='virtual network address prefix(s) (e.g. 10.0.0.0/8, 192.168.0.0/16')
    azure.add_argument('--lun', type=str, required=False, help='logical (disk) unit number (LUN)')
    azure.add_argument('--location', type=str, required=False, help='resource location')
    azure.add_argument('--publisher', type=str, required=False, default=AzureCloudClass.default_publisher, help='resource extension publisher name (default: %s)' % AzureCloudClass.default_publisher)
    azure.add_argument('--extension', type=str, required=False, default=AzureCloudClass.default_extension, help='resource extension name (default: %s)' % AzureCloudClass.default_extension)
    azure.add_argument('--vmaop', type=str, required=False, default=AzureCloudClass.default_vmaop, choices=['ResetRDPConfig', 'ResetSSHKey', 'ResetSSHKeyAndPassword', 'ResetPassword', 'DeleteUser', 'ResetSSHConfig'], help='VMAccess operation (default: %s)' % AzureCloudClass.default_vmaop)
    azure.add_argument('--patching_disabled', action='store_true', required=False, help='OSPatching disable patching')
    azure.add_argument('--patching_stop', action='store_true', required=False, help='OSPatching stop patching')
    azure.add_argument('--patching_reboot_after', type=str, required=False, default=AzureCloudClass.default_patching_reboot_after, choices=['Auto', 'Required', 'NotRequired'], help='OSPatching reboot after patching (default: %s)' % AzureCloudClass.default_patching_reboot_after)
    azure.add_argument('--patching_interval', type=int, required=False, default=AzureCloudClass.default_patching_interval, help='OSPatching interval (default: %i)' % AzureCloudClass.default_patching_interval)
    azure.add_argument('--patching_day', type=str, required=False, default=AzureCloudClass.default_patching_day, help='OSPatching patching day (default: %s)' % AzureCloudClass.default_patching_day)
    azure.add_argument('--patching_starttime', type=str, required=False, default=AzureCloudClass.default_patching_starttime, help='OSPatching patching start time HH:MM (default: one off)')
    azure.add_argument('--patching_category', type=str, required=False, default=AzureCloudClass.default_patching_category, choices=['ImportantAndRecommended', 'Important'], help='OSPatching patching catgory (default: %s)' % AzureCloudClass.default_patching_category)
    azure.add_argument('--patching_duration', type=str, required=False, default=AzureCloudClass.default_patching_duration, help='OSPatching patching duration (default: %s)' % AzureCloudClass.default_patching_duration)
    azure.add_argument('--patching_local', action='store_true', required=False, help='OSPatching patching local')
    azure.add_argument('--patching_oneoff', action='store_true', required=False, help='OSPatching patching one-off')
    azure.add_argument('--eula_uri', type=str, required=False, help='VM image EULA URI')
    azure.add_argument('--privacy_uri', type=str, required=False, help='VM image privacy URI')
    azure.add_argument('--icon_uri', type=str, required=False, help='VM image icon URI')
    azure.add_argument('--small_icon_uri', type=str, required=False, help='VM image small icon URI')
    azure.add_argument('--show_in_gui', action='store_true', required=False, help='show VM image in GUI')
    azure.add_argument('--docker_port', type=str, required=False, default=AzureCloudClass.default_docker_port, help='Docker TCP port (default: %s)' % AzureCloudClass.default_docker_port)
    azure.add_argument('--docker_options', type=str, nargs='+', required=False, default=AzureCloudClass.default_docker_options, help='Docker options (default: %s)' % AzureCloudClass.default_docker_options)
    azure.add_argument('--docker_username', type=str, required=False, default=AzureCloudClass.default_docker_username, help='Docker registry server username (default: %s)' % AzureCloudClass.default_docker_username)
    azure.add_argument('--docker_password', type=str, required=False, default=AzureCloudClass.default_docker_password, help='Docker registry password (default: %s)' % AzureCloudClass.default_docker_password)
    azure.add_argument('--docker_email', type=str, required=False, default=AzureCloudClass.default_docker_email, help='Docker registry server email (default: %s)' % AzureCloudClass.default_docker_email)
    azure.add_argument('--docker_ca_certificate', type=str, required=False, default=AzureCloudClass.default_docker_ca_certificate, help='Docker CA certificate for TSL configuration (default: %s)' % AzureCloudClass.default_docker_ca_certificate)
    azure.add_argument('--docker_server_certificate', type=str, required=False, default=AzureCloudClass.default_docker_server_certificate, help='Docker server certificate for TSL configuration (default: %s)' % AzureCloudClass.default_docker_server_certificate)
    azure.add_argument('--docker_server_key', type=str, required=False, default=AzureCloudClass.default_docker_server_key, help='Docker server private key for TSL configuration (default: %s)' % AzureCloudClass.default_docker_server_key)
    azure.add_argument('--docker_registry_server', type=str, required=False, help='Docker registry server (default: DockerHub)')
    args = parser.parse_args()
    logger(message=str(args))
    return args

def logger(message=None):
    if BaseCloudHarnessClass.debug: sys.stderr.write('DEBUG %s\n' % repr(message))
    if BaseCloudHarnessClass.log: logging.info('%s\n' % repr(message))         

class BaseCloudHarnessClass():
    log = False
    debug = True
    log_file = '%s' % os.path.basename(__file__).replace('py', 'log')
    config_file = '%s' % os.path.basename(__file__).replace('py', 'conf')
    cp = ConfigParser.SafeConfigParser()        
    try:
        with open(config_file) as cf:
            cp.readfp(cf)
    except IOError:
        pass

    default_subscription_id = None
    default_management_certificate = None
    default_docker_port = None
    default_docker_options = None
    default_docker_username = None
    default_docker_password = None
    default_docker_email = None
    default_docker_ca_certificate = None
    default_docker_server_certificate = None
    default_docker_server_key = None
    default_chef_server_url = None
    default_chef_validation_client_name = None
    default_chef_validation_key_file = None
    default_chef_run_list = None
    default_docker_port = None
    default_docker_options = None
    default_docker_username = None
    default_docker_password = None
    default_docker_email = None
    default_docker_ca_certificate = None
    default_docker_server_certificate = None
    default_docker_server_key = None
    default_windows_customscript_name = None
    default_linux_customscript_name = None
    default_remote_subnets = None
    default_certificate = None
    default_storage_account = None
    default_storage_container = None
    default_chef_autoupdate_client = None
    default_chef_delete_config = None
    default_chef_verify_api_cert = None
    default_chef_ssl_verify_mode = None
    default_patching_healthy_test_script = None
    default_patching_idle_test_script = None
    default_linux_custom_data_file = None
    default_windows_custom_data_file = None
    default_location = None
    proxy = False
    proxy_host = None
    proxy_port = None
    ssl_verify = False

    try:
        default_subscription_id = dict(cp.items('AzureConfig'))['subscription_id']
        default_management_certificate = dict(cp.items('AzureConfig'))['management_certificate']        
        proxy = dict(cp.items('AzureConfig'))['proxy']
        proxy_host = dict(cp.items('AzureConfig'))['proxy_host']
        proxy_port = dict(cp.items('AzureConfig'))['proxy_port']
        ssl_verify = dict(cp.items('AzureConfig'))['ssl_verify']
        default_location = dict(cp.items('AzureConfig'))['location_name']
        default_chef_server_url = dict(cp.items('ChefClient'))['chef_server_url']
        default_chef_validation_client_name = dict(cp.items('ChefClient'))['chef_validation_client_name']
        default_chef_validation_key_file = dict(cp.items('ChefClient'))['chef_validation_key_file']
        default_chef_run_list = dict(cp.items('ChefClient'))['chef_run_list']
        default_chef_autoupdate_client = dict(cp.items('ChefClient'))['chef_autoupdate_client']
        default_chef_delete_config = dict(cp.items('ChefClient'))['chef_delete_config']
        default_chef_ssl_verify_mode = dict(cp.items('ChefClient'))['chef_ssl_verify_mode']
        default_chef_verify_api_cert = dict(cp.items('ChefClient'))['chef_verify_api_cert']        
        default_windows_customscript_name = dict(cp.items('CustomScriptExtensionForWindows'))['windows_customscript_name']
        default_linux_customscript_name = dict(cp.items('CustomScriptExtensionForLinux'))['linux_customscript_name']
        default_remote_subnets = cp.items('DefaultEndpointACL')
        default_certificate = dict(cp.items('LinuxConfiguration'))['service_certificate']      
        default_linux_custom_data_file = dict(cp.items('LinuxConfiguration'))['linux_custom_data_file']
        default_windows_custom_data_file = dict(cp.items('WindowsConfiguration'))['windows_custom_data_file']
        default_storage_account = dict(cp.items('AzureConfig'))['storage_account']
        default_storage_container = dict(cp.items('AzureConfig'))['storage_container']
        default_patching_healthy_test_script = dict(cp.items('OSPatchingExtensionForLinux'))['patching_healthy_test_script']        
        default_patching_idle_test_script = dict(cp.items('OSPatchingExtensionForLinux'))['patching_idle_test_script']
        default_docker_port = dict(cp.items('DockerExtension'))['docker_port']
        default_docker_options = dict(cp.items('DockerExtension'))['docker_options']
        default_docker_username = dict(cp.items('DockerExtension'))['docker_username']
        default_docker_password = dict(cp.items('DockerExtension'))['docker_password']
        default_docker_email = dict(cp.items('DockerExtension'))['docker_email']
        default_docker_ca_certificate = dict(cp.items('DockerExtension'))['docker_ca_certificate']
        default_docker_server_certificate = dict(cp.items('DockerExtension'))['docker_server_certificate']
        default_docker_server_key = dict(cp.items('DockerExtension'))['docker_server_key']
    except:
        pass
    
class AzureCloudClass(BaseCloudHarnessClass):
    default_action = 'list_locations'
    actions = [{'action': 'x_ms_version', 'params': [], 'collection': False},
               {'action': 'host', 'params': [], 'collection': False},
               {'action': 'cert_file', 'params': [], 'collection': False},
               {'action': 'content_type', 'params': [], 'collection': False},
               {'action': 'timeout', 'params': [], 'collection': False},
               {'action': 'sub_id', 'params': [], 'collection': False},
               {'action': 'request_session', 'params': [], 'collection': False},
               {'action': 'requestid', 'params': [], 'collection': False},
               {'action': 'list_collection', 'params': ['action'], 'collection': False},
               {'action': 'list_dns_servers', 'params': ['service', 'deployment'], 'collection': False},
               {'action': 'list_affinity_groups', 'params': [], 'collection': True},
               {'action': 'list_disks', 'params': [], 'collection': True},
               {'action': 'list_hosted_services', 'params': [], 'collection': True},
               {'action': 'list_locations', 'params': [], 'collection': True},
               {'action': 'list_management_certificates', 'params': [], 'collection': True},
               {'action': 'list_operating_system_families', 'params': [], 'collection': True},
               {'action': 'list_os_images', 'params': [], 'collection': True},
               {'action': 'list_reserved_ip_addresses', 'params': [], 'collection': True},
               {'action': 'list_resource_extension_versions', 'params': [], 'collection': False},
               {'action': 'list_resource_extensions', 'params': [], 'collection': True},
               {'action': 'list_role_sizes', 'params': [], 'collection': True},
               {'action': 'list_service_certificates', 'params': ['service'], 'collection': False},
               {'action': 'list_storage_accounts', 'params': [], 'collection': True},
               {'action': 'list_subscription_operations', 'params': [], 'collection': False},
               {'action': 'list_subscriptions', 'params': [], 'collection': True},
               {'action': 'list_virtual_network_sites', 'params': ['action'], 'collection': True},
               {'action': 'list_vm_images', 'params': [], 'collection': True},
               {'action': 'add_resource_extension', 'params': ['service', 'deployment', 'name', 'extension'], 'collection': False},
               {'action': 'add_role', 'params': ['deployment', 'service', 'os', 'name', 'blob', 'subnet', 'account'], 'collection': False},
               {'action': 'add_data_disk', 'params': ['service', 'deployment', 'name'], 'collection': False},
               {'action': 'add_disk', 'params': ['name', 'os', 'blob'], 'collection': False},
               {'action': 'add_dns_server', 'params': ['service', 'deployment', 'dns', 'ipaddr'], 'collection': False},
               {'action': 'add_management_certificate', 'params': ['certificate'], 'collection': False},
               {'action': 'add_os_image', 'params': ['name', 'blob', 'os'], 'collection': False},
               {'action': 'add_service_certificate', 'params': ['service'], 'collection': False},
               {'action': 'build_epacls_dict_from_xml', 'params': ['deployment', 'service', 'name'], 'collection': False},
               {'action': 'build_chefclient_resource_extension', 'params': ['os'], 'collection': False},
               {'action': 'build_customscript_resource_extension', 'params': ['os'], 'collection': False},
               {'action': 'build_vmaccess_resource_extension', 'params': ['os'], 'collection': False},
               {'action': 'build_ospatching_resource_extension', 'params': ['os'], 'collection': False},
               {'action': 'build_docker_resource_extension', 'params': ['os'], 'collection': False},
               {'action': 'build_resource_extension_dict', 'params': ['os', 'extension', 'publisher', 'version'], 'collection': False},
               {'action': 'build_resource_extensions_xml_from_dict', 'params': ['extensions'], 'collection': False},
               {'action': 'check_hosted_service_name_availability', 'params': ['service'], 'collection': False},
               {'action': 'check_storage_account_name_availability', 'params': ['account'], 'collection': False},
               {'action': 'create_affinity_group', 'params': ['name'], 'collection': False},
               {'action': 'create_hosted_service', 'params': ['service', 'label'], 'collection': False},
               {'action': 'create_virtual_machine_deployment', 'params': ['deployment', 'service', 'os', 'name', 'blob', 'subnet', 'account', 'network'], 'collection': False},
               {'action': 'create_virtual_network_site', 'params': ['dns', 'ipaddr', 'network', 'subnet', 'subnetaddr', 'vnetaddr'], 'collection': False},
               {'action': 'change_deployment_configuration', 'params': ['service', 'deployment', 'package_config'], 'collection': False},
               {'action': 'create_storage_account', 'params': ['account'], 'collection': False},
               {'action': 'capture_role', 'params': ['service', 'deployment', 'name', 'blob'], 'collection': False},
               {'action': 'capture_vm_image', 'params': ['service', 'deployment', 'name', 'blob'], 'collection': False},
               {'action': 'create_deployment', 'params': ['service', 'deployment', 'name', 'package_url', 'package_config'], 'collection': False},
               {'action': 'create_reserved_ip_address', 'params': ['ipaddr'], 'collection': False},
               {'action': 'create_vm_image', 'params': ['blob', 'os'], 'collection': False},
               {'action': 'delete_affinity_group', 'params': ['name'], 'collection': False},
               {'action': 'delete_role', 'params': ['deployment', 'service', 'name'], 'collection': False},
               {'action': 'delete_os_image', 'params': ['name'], 'collection': False},
               {'action': 'delete_disk', 'params': ['disk'], 'collection': False},
               {'action': 'delete_disk_blob', 'params': ['blob'], 'collection': False},
               {'action': 'delete_deployment', 'params': ['service', 'deployment'], 'collection': False},
               {'action': 'delete_dns_server', 'params': ['service', 'deployment', 'dns'], 'collection': False},
               {'action': 'delete_management_certificate', 'params': ['thumbprint'], 'collection': False},
               {'action': 'delete_service_certificate', 'params': ['service', 'thumbprint'], 'collection': False},
               {'action': 'delete_hosted_service', 'params': ['service'], 'collection': False},
               {'action': 'delete_reserved_ip_address', 'params': ['ipaddr'], 'collection': False},
               {'action': 'delete_storage_account', 'params': ['account'], 'collection': False},
               {'action': 'delete_role_instances', 'params': ['service', 'deployment', 'name'], 'collection': False},
               {'action': 'delete_data_disk', 'params': ['service', 'deployment', 'name', 'lun'], 'collection': False},
               {'action': 'delete_vm_image', 'params': ['name'], 'collection': False},
               {'action': 'get_certificate_from_publish_settings', 'params': [], 'collection': False},
               {'action': 'get_storage_account_properties', 'params': [], 'collection': False},
               {'action': 'get_deployment_by_slot', 'params': ['service'], 'collection': False},
               {'action': 'get_deployment_by_name', 'params': ['service', 'deployment'], 'collection': False},
               {'action': 'get_role', 'params': ['service', 'deployment', 'name'], 'collection': False},
               {'action': 'get_data_disk', 'params': ['name', 'service', 'deployment'], 'collection': False},
               {'action': 'get_disk', 'params': ['disk'], 'collection': False},
               {'action': 'get_hosted_service_properties', 'params': ['service'], 'collection': False},
               {'action': 'get_management_certificate', 'params': ['thumbprint'], 'collection': False},
               {'action': 'get_operation_status', 'params': ['request_id'], 'collection': False},
               {'action': 'get_os_image', 'params': ['name'], 'collection': False},
               {'action': 'get_reserved_ip_address', 'params': ['ipaddr'], 'collection': False},
               {'action': 'get_service_certificate', 'params': ['service', 'thumbprint'], 'collection': False},
               {'action': 'get_storage_account_keys', 'params': ['account'], 'collection': False},
               {'action': 'get_subscription', 'params': [], 'collection': False},
               {'action': 'get_affinity_group_properties', 'params': ['name'], 'collection': False},
               {'action': 'get_hosted_service_properties', 'params': ['service'], 'collection': False},
               {'action': 'get_disk_by_role_name', 'params': ['service', 'deployment', 'name'], 'collection': False},
               {'action': 'get_objs_for_role', 'params': ['deployment', 'service', 'name'], 'collection': False},
               {'action': 'get_pub_key_and_thumbprint_from_x509_cert', 'params': ['certificate', 'algorithm'], 'collection': False},
               {'action': 'generate_signed_blob_url', 'params': ['account', 'container', 'script'], 'collection': False},
               {'action': 'get_epacls', 'params': ['service', 'deployment', 'name'], 'collection': False},
               {'action': 'perform_get', 'params': ['path'], 'collection': False},
               {'action': 'perform_put', 'params': ['path', 'body'], 'collection': False},
               {'action': 'perform_delete', 'params': ['path'], 'collection': False},
               {'action': 'perform_post', 'params': ['path', 'body'], 'collection': False},
               {'action': 'upload_blob', 'params': ['blob'], 'collection': False},
               {'action': 'set_epacls', 'params': ['service', 'deployment', 'name', 'subnet'], 'collection': False},
               {'action': 'reboot_role_instance', 'params': ['service', 'deployment', 'name'], 'collection': False},
               {'action': 'start_role', 'params': ['service', 'deployment', 'name'], 'collection': False},
               {'action': 'start_roles', 'params': ['service', 'deployment', 'name'], 'collection': False},
               {'action': 'restart_role', 'params': ['service', 'deployment', 'name'], 'collection': False},
               {'action': 'rebuild_role_instance', 'params': ['service', 'deployment', 'name'], 'collection': False},
               {'action': 'regenerate_storage_account_keys', 'params': ['account'], 'collection': False},
               {'action': 'reimage_role_instance', 'params': ['service', 'deployment', 'name'], 'collection': False},
               {'action': 'rollback_update_or_upgrade', 'params': ['service', 'deployment'], 'collection': False},
               {'action': 'swap_deployment', 'params': ['service', 'deployment', 'production_deployment'], 'collection': False},
               {'action': 'shutdown_role', 'params': ['service', 'deployment', 'name'], 'collection': False},
               {'action': 'shutdown_roles', 'params': ['service', 'deployment', 'name'], 'collection': False},
               {'action': 'update_affinity_group', 'params': ['name'], 'collection': False},
               {'action': 'update_data_disk', 'params': [], 'collection': False},
               {'action': 'update_deployment_status', 'params': ['service', 'deployment', 'deployment_status'], 'collection': False},
               {'action': 'update_disk', 'params': ['disk'], 'collection': False},
               {'action': 'update_dns_server', 'params': ['service', 'deployment', 'dns', 'ipaddr'], 'collection': False},
               {'action': 'update_hosted_service', 'params': [], 'collection': False},
               {'action': 'update_os_image', 'params': ['blob', 'name'], 'collection': False},
               {'action': 'update_role', 'params': ['deployment', 'service', 'name'], 'collection': False},
               {'action': 'update_storage_account', 'params': [], 'collection': False},
               {'action': 'update_vm_image', 'params': ['name'], 'collection': False},
               {'action': 'upgrade_deployment', 'params': ['service', 'deployment', 'name', 'package_url', 'package_config'], 'collection': False},
               {'action': 'wait_for_operation_status', 'params': [], 'collection': False},
               {'action': 'wait_for_vm_provisioning_completion', 'params': ['service', 'deployment', 'name'], 'collection': False},
               {'action': 'walk_upgrade_domain', 'params': ['service', 'deployment', 'upgrade_domain'], 'collection': False},
               {'action': 'xml_networkconfig_fragment_from_dict', 'params': ['dns', 'ipaddr', 'network', 'subnet', 'subnetaddr', 'vnetaddr'], 'collection': False},
               {'action': 'xml_endpoint_fragment_from_dict', 'params': ['epacls'], 'collection': False}]

    default_end_date = datetime.now()
    default_start_date = default_end_date - timedelta(days=7)
    default_publisher = 'Microsoft.Compute'
    default_extension = 'CustomScriptExtension'
    default_deployment_slot = 'Production'
    default_size = 'Medium'
    default_disk_size = 30
    default_user_name = 'azureuser'
    default_status = 'Succeeded'
    default_wait = 15
    default_timeout = 300    
    default_endpoints = {'Windows': [{'LocalPort': '5985',
                                      'Name': 'WinRM',
                                      'Port': str(randint(49152,65535)),
                                      'Protocol': 'tcp'},
                                     {'LocalPort': '5986',
                                      'Name': 'PowerShell',
                                      'Port': str(randint(49152,65535)),
                                      'Protocol': 'tcp'}],
                         'Linux': [{'LocalPort': '22',
                                    'Name': 'SSH',
                                    'Port': str(randint(49152,65535)),
                                    'Protocol': 'tcp'}]}    
    default_algorithm = 'SHA1'
    default_chef_autoupdate_client = True
    default_chef_delete_config = False
    default_vmaop = 'ResetPassword'
    default_pwd_expiry = 365
    default_patching_reboot_after = 'Auto'
    default_patching_interval = 1
    default_patching_day = 'Everyday'
    default_patching_starttime = ''
    default_patching_category = 'ImportantAndRecommended'
    default_patching_duration = '03:00'
    default_host_caching = 'ReadWrite'
    default_post_capture_action = 'Reprovision'
    default_os_state = 'Specialized'
    default_start_deployment = False
    default_ignore_warinings = False
    default_account_type = 'Standard_GRS'
    default_key_type = 'Primary'
    default_mode = 'auto'
    default_blobtype = 'page'

    def __init__(self, subscription_id=None, management_certificate=None):
        self.subscription_id = subscription_id or self.default_subscription_id
        self.management_certificate = management_certificate or self.default_management_certificate

        if not self.subscription_id or not self.management_certificate:
            for psf in os.listdir("."):
                if psf.endswith(".publishsettings"):
                    self.publish_settings = psf
                    break
        
            if self.publish_settings:
                self.management_certificate = 'management_certificate.pem'
                self.subscription_id = get_certificate_from_publish_settings(self.publish_settings,
                                                                             path_to_write_certificate=self.management_certificate,
                                                                             subscription_id=None)
                
                self.cp.set('AzureConfig', 'subscription_id', self.subscription_id)
                self.cp.set('AzureConfig', 'management_certificate', self.management_certificate)
                try:
                    with open(self.config_file, 'wb') as cf:
                        self.cp.write(cf)
                except IOError:
                    logger('%s: failed to update configuration file %s' % (inspect.stack()[0][3],
                                                                           self.config_file))
                    sys.exit(1)
                    
                if not self.subscription_id:
                    logger('%s: failed to extract management certificate fom PublishSettings' % inspect.stack()[0][3])
                    sys.exit(1)
                else:
                    logger('%s: written Azure management_certificate.pem for subscription_id %s' % (inspect.stack()[0][3],                                                                                               self.subscription_id))
            else:
                logger('%s: requires an Azure subscription_id and management_certificate (PublishSettings file not found)' % inspect.stack()[0][3])
                sys.exit(1)

        self.sms = ServiceManagementService(self.subscription_id,
                                            self.management_certificate,
                                            request_session=self.set_proxy())

    def add_resource_extension(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False
            
            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.name = self.get_params(key='name', params=arg, default=None)
            if isinstance(self.name, list): self.name = self.name[0]
            self.os = self.get_params(key='os', params=arg, default=self.get_role({'service': self.service,
                                                                                   'deployment': self.deployment,
                                                                                   'name': self.name,
                                                                                   'verbose': False})['os_virtual_hard_disk']['os'])
            arg['os'] = self.os
            if arg['extension'] == 'ChefClient':                    
                arg['rextrs'] = self.build_chefclient_resource_extension(arg)                
                return self.update_role(arg)
            elif arg['extension'] == 'CustomScript':
                arg['rextrs'] = az.build_customscript_resource_extension(arg)
                return self.update_role(arg)
            elif arg['extension'] == 'VMAccessAgent':
                arg['rextrs'] = az.build_vmaccess_resource_extension(arg)
                return self.update_role(arg)
            elif arg['extension'] == 'OSPatching':
                arg['rextrs'] = az.build_ospatching_resource_extension(arg)
                return self.update_role(arg)                
            elif arg['extension'] == 'DockerExtension':
                arg['rextrs'] = az.build_docker_resource_extension(arg)
                return self.update_role(arg)                
            else:
                logger('%s: unsupported extension %s' % (inspect.stack()[0][3], self.extension))

        except Exception as e:
            logger(message=traceback.print_exc())
            return False
    
    def add_role(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.name = self.get_params(key='name', params=arg, default=None)
            if isinstance(self.name, list): self.name = self.name[0]
            self.os = self.get_params(key='os', params=arg, default=None)
            self.blob = self.get_params(key='blob', params=arg, default=None)
            if isinstance(self.blob, list): self.blob = self.blob[0]
            self.account = self.get_params(key='account', params=arg, default=None)
            self.subnet = self.get_params(key='subnet', params=arg, default=None)
            if isinstance(self.subnet, list): self.subnet = self.subnet[0]
            self.container = self.get_params(key='container', params=arg, default=self.default_storage_container)
            self.label = self.get_params(key='label', params=arg, default=self.name)
            self.availset = self.get_params(key='availset', params=arg, default=None)
            self.password = self.get_params(key='password', params=arg, default=''.join(SystemRandom().choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for _ in range(11)))
            self.slot = self.get_params(key='slot', params=arg, default=self.default_deployment_slot)            
            self.size = self.get_params(key='size', params=arg, default=self.default_size)
            self.username = self.get_params(key='username', params=arg, default=self.default_user_name)        
            self.eps = self.get_params(key='eps', params=arg, default=self.default_endpoints)
            self.rextrs = self.get_params(key='rextrs', params=arg, default=None)
            self.certificate = self.get_params(key='certificate', params=arg, default=self.default_certificate)
            self.algorithm = self.get_params(key='algorithm', params=arg, default=self.default_algorithm)
            self.async = self.get_params(key='async', params=arg, default=None)    
            self.readonly = self.get_params(key='readonly', params=arg, default=None)                
            self.ssh_auth = self.get_params(key='ssh_auth', params=arg, default=None)                
            self.disable_pwd_auth = self.get_params(key='disable_pwd_auth', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)
 
            if self.os == 'Windows':
                self.custom_data_file = self.get_params(key='custom_data_file', params=arg, default=self.default_windows_custom_data_file)
                try:
                    self.custom_data = None                                                    
                    with open(self.custom_data_file, 'rb') as cf:
                        self.custom_data = b64encode(cf.read())
                except IOError:
                    logger('%s: unable to read %s' % (inspect.stack()[0][3], self.custom_data_file))
                    pass

            if self.os == 'Linux':
                self.custom_data_file = self.get_params(key='custom_data_file', params=arg, default=self.default_linux_custom_data_file)
                try:
                    self.custom_data = None                                                    
                    with open(self.custom_data_file, 'rb') as cf:
                        self.custom_data = cf.read()
                except IOError:
                    logger('%s: unable to read %s' % (inspect.stack()[0][3], self.custom_data_file))
                    pass                                                                        

            net_config = ConfigurationSet()
            net_config.configuration_set_type = 'NetworkConfiguration'
            subnet = Subnet()
            subnet.name = self.subnet           
            subnets = Subnets()
            subnets.subnets.append(subnet.name)
            net_config.subnet_names = subnets
           
            endpoints = []                        
            if self.os in ['Windows']:
                self.os_config = WindowsConfigurationSet(computer_name=self.name,
                                                         admin_password=self.password,
                                                         reset_password_on_first_logon=None,
                                                         enable_automatic_updates=None,
                                                         time_zone=None,
                                                         admin_username=self.username,
                                                         custom_data=self.custom_data)
                self.os_config.domain_join = None
                self.os_config.win_rm = None
                self.os_config.stored_certificate_settings = None
                self.os_config.additional_unattend_content = None
                
                for ep in self.eps[self.os]:
                    endpoints.append(ConfigurationSetInputEndpoint(name=ep['Name'],
                                                                   protocol=ep['Protocol'],
                                                                   port=ep['Port'],
                                                                   local_port=ep['LocalPort'],
                                                                   load_balanced_endpoint_set_name=None,
                                                                   enable_direct_server_return=False))                    
                for endpoint in endpoints:
                    net_config.input_endpoints.input_endpoints.append(endpoint)

            endpoints = []                
            if self.os in ['Linux']:
                if self.disable_pwd_auth:
                    self.password = None
                    self.ssh_auth = True
                    
                self.os_config = LinuxConfigurationSet(host_name=self.name,
                                                       user_name=self.username,
                                                       user_password=self.password,
                                                       disable_ssh_password_authentication=self.ssh_auth,
                                                       custom_data=self.custom_data)                    
                if self.ssh_auth:
                    ssh = SSH()
                    pks = PublicKeys()
                    pk = PublicKey()
                    pk.path = '/home/%s/.ssh/authorized_keys' % self.username

                    result = self.get_pub_key_and_thumbprint_from_x509_cert(certificate=self.certificate, algorithm=self.algorithm)
                    self.thumbprint = result['thumbprint']
                    pk.fingerprint = self.thumbprint
                   
                    pks.public_keys.append(pk)
                    ssh.public_keys = pks
                    self.os_config.ssh = ssh

                for ep in self.eps[self.os]:
                    endpoints.append(ConfigurationSetInputEndpoint(name=ep['Name'],
                                                                   protocol=ep['Protocol'],
                                                                   port=ep['Port'],
                                                                   local_port=ep['LocalPort'],
                                                                   load_balanced_endpoint_set_name=None,
                                                                   enable_direct_server_return=False))
                for endpoint in endpoints:
                    net_config.input_endpoints.input_endpoints.append(endpoint)
                
            self.net_config = net_config            
            ts = mkdate(datetime.now(), '%Y-%m-%d-%H-%M-%S-%f')            
            self.media_link = 'https://%s.blob.core.windows.net/%s/%s-%s-%s-0.vhd' % (self.account,
                                                                                      self.container,
                                                                                      self.service,
                                                                                      self.name,
                                                                                      ts)
            self.disk_config = OSVirtualHardDisk(source_image_name=self.blob,
                                                 media_link=self.media_link,
                                                 host_caching=None,
                                                 disk_label=None,
                                                 disk_name=None,
                                                 os=None,
                                                 remote_source_image_link=None)
            
            if verbose: pprint.pprint(self.__dict__)            

            if not self.readonly:
                try:
                    d = dict()
                    result = self.sms.add_role(self.service, self.deployment, self.name,
                                               self.os_config, self.disk_config, network_config=self.net_config,
                                               availability_set_name=self.availset, data_virtual_hard_disks=None, role_size=self.size,
                                               role_type='PersistentVMRole', resource_extension_references=self.rextrs,
                                               provision_guest_agent=True, vm_image_name=None, media_location=None)
                    d['result'] = result.__dict__
                    if not self.async:
                        operation = self.sms.get_operation_status(result.request_id)
                        d['operation'] = operation.__dict__
                        d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                        return d
                    else:
                        return 
                except (WindowsAzureConflictError) as e:
                    logger('%s: operation in progress or resource exists, try again..' % inspect.stack()[0][3])
                    return False
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def add_data_disk(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.name = self.get_params(key='name', params=arg, default=None)
            if isinstance(self.name, list): self.name = self.name[0]
            self.lun = self.get_params(key='lun',
                                                params=arg,
                                                default=len(self.get_disk_by_role_name({'service': self.service,
                                                                                        'deployment': self.deployment,
                                                                                        'name': self.name,
                                                                                        'verbose': False})))
            self.blob = self.get_params(key='blob', params=arg, default=None)
            if isinstance(self.blob, list): self.blob = self.blob[0]
            self.disk = self.get_params(key='disk', params=arg, default=None)
            self.label = self.get_params(key='label', params=arg, default=None)
            self.account = self.get_params(key='account', params=arg, default=self.default_storage_account)
            self.container = self.get_params(key='container', params=arg, default=self.default_storage_container)       
            self.host_caching = self.get_params(key='host_caching', params=arg, default=self.default_host_caching)
            self.disk_size = self.get_params(key='disk_size', params=arg, default=self.default_disk_size)            
            self.async = self.get_params(key='async', params=arg, default=None)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)

            ts = mkdate(datetime.now(), '%Y-%m-%d-%H-%M-%S-%f')
            if self.blob:
                self.media_link = None
                self.source_media_link = 'https://%s.blob.core.windows.net/%s/%s' % (self.account,
                                                                                     self.container,
                                                                                     self.blob)
            elif self.disk:
                self.source_media_link = None
                self.media_link = None             
            else:
                self.source_media_link = None
                self.media_link = 'https://%s.blob.core.windows.net/%s/%s-%s-%s-%s.vhd' % (self.account,
                                                                                           self.container,
                                                                                           self.service,
                                                                                           self.name,
                                                                                           ts,
                                                                                           self.lun)
            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                try:
                    result = self.sms.add_data_disk(self.service, self.deployment, self.name, self.lun,
                                                    host_caching=self.host_caching,
                                                    media_link=self.media_link,
                                                    disk_label=self.label,
                                                    disk_name=self.disk,
                                                    logical_disk_size_in_gb=self.disk_size,
                                                    source_media_link=self.source_media_link)
                    d = dict()
                    operation = self.sms.get_operation_status(result.request_id)
                    d['result'] = result.__dict__
                    d['operation'] = operation.__dict__
                    if not self.async:
                        d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                        return d
                    else:
                        return d
                except (WindowsAzureConflictError) as e:
                    logger('%s: operation in progress or resource exists, try again..' % inspect.stack()[0][3])
                    return False
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
        
    def add_disk(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.os = self.get_params(key='os', params=arg, default=None)
            self.name = self.get_params(key='name', params=arg, default=None)
            if isinstance(self.name, list): self.name = self.name[0]
            self.blob = self.get_params(key='blob', params=arg, default=None)
            if isinstance(self.blob, list): self.blob = self.blob[0]
            self.label = self.get_params(key='label', params=arg, default=self.name)
            self.account = self.get_params(key='account', params=arg, default=self.default_storage_account)
            self.container = self.get_params(key='container', params=arg, default='images')       
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)

            self.media_link = 'https://%s.blob.core.windows.net/%s/%s' % (self.account, self.container, self.blob)
            
            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                try:
                    return self.sms.add_disk(None, self.label, self.media_link, self.name, self.os)
                except (WindowsAzureConflictError) as e:
                    logger('%s: operation in progress or resource exists, try again..' % inspect.stack()[0][3])
                    return False
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def add_dns_server(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.dns = self.get_params(key='dns', params=arg, default=None)
            if isinstance(self.dns, list): self.dns = self.dns[0]
            self.ipaddr = self.get_params(key='ipaddr', params=arg, default=None)
            if isinstance(self.ipaddr, list): self.ipaddr = self.ipaddr[0]
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)
            self.async = self.get_params(key='async', params=arg, default=None)

            if verbose: pprint.pprint(self.__dict__)
            
            result = self.sms.add_dns_server(self.service, self.deployment, self.dns, self.ipaddr)        
            if result is not None:
                if not self.readonly:
                    d = dict()
                    operation = self.sms.get_operation_status(result.request_id)
                    d['result'] = result.__dict__
                    d['operation'] = operation.__dict__
                    if not self.async:
                        d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                        return d
                    else:
                        return d
                else:
                    logger('%s: limited to read-only operations' % inspect.stack()[0][3])
            else:
                return False
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def get_pub_key_and_thumbprint_from_x509_cert(self, **kwargs):
        try:
            if not kwargs: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=kwargs)
            if not arg: return False

            self.certificate = self.get_params(key='certificate', params=arg, default=self.default_certificate)
            self.algorithm = self.get_params(key='algorithm', params=arg, default=self.default_algorithm)
            
            try:
                cert = pyopenssl.load_certificate(pyopenssl.FILETYPE_ASN1, open(self.certificate).read())
            except IOError:
                logger('%s: unable to read %s' % (inspect.stack()[0][3], self.certificate))
                return False
            
            pub_key = cert.get_pubkey()            
            pub_asn1 = pyopenssl.dump_privatekey(pyopenssl.FILETYPE_ASN1, pub_key)            
            pub_der = asn1.DerSequence()            
            pub_der.decode(pub_asn1)
            rsa_key = RSA.construct((pub_der[1], pub_der[2]))            
            pub_der[:] = [ rsa_key.key.n, rsa_key.key.e ]
            d = dict()
            d['certificate'] = b64encode(pyopenssl.dump_certificate(pyopenssl.FILETYPE_ASN1, cert))            
            d['public_key'] = b64encode(pub_der.encode())            
            d['thumbprint'] = cert.digest(self.algorithm).replace(':', '')
            return d
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
    
    def add_management_certificate(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False
            
            self.algorithm = self.get_params(key='algorithm', params=arg, default=self.default_algorithm)
            self.certificate = self.get_params(key='certificate', params=arg, default=None)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)

            result = self.get_pub_key_and_thumbprint_from_x509_cert(certificate=self.certificate, algorithm=self.algorithm)
            self.certificate = result['certificate']
            self.public_key = result['public_key']
            self.thumbprint = result['thumbprint']

            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                result = self.sms.add_management_certificate(self.public_key, self.thumbprint, self.certificate)     
                if result is not None:
                        d = dict()
                        operation = self.sms.get_operation_status(result.request_id)
                        d['result'] = result.__dict__
                        d['operation'] = operation.__dict__
                        if not self.async:
                            d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                            return d
                        else:
                            return d
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def delete_disk_blob(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False
            
            self.blob = self.get_params(key='blob', params=arg, default=None)
            if isinstance(self.blob, list): self.blob = self.blob[0]
            self.account = self.get_params(key='account', params=arg, default=self.default_storage_account)
            self.key = self.get_storage_account_keys({'account': self.account,
                                                      'verbose': False})['storage_service_keys']['primary']
            self.container = self.get_params(key='container', params=arg, default=self.default_storage_container)       
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)
           
            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:                
                blob_service = BlobService(self.account, self.key)                
                with open(self.blob) as f:
                    result = blob_service.delete_blob(self,
                                                      self.container,
                                                      self.blob,
                                                      snapshot=None,
                                                      timeout=None,
                                                      x_ms_lease_id=None,
                                                      x_ms_delete_snapshots=None)
                return result
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def upload_blob(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False
            
            self.blob = self.get_params(key='blob', params=arg, default=None)
            if isinstance(self.blob, list): self.blob = self.blob[0]
            self.disk_size = os.stat(self.blob).st_size
            self.account = self.get_params(key='account', params=arg, default=self.default_storage_account)
            self.key = self.get_storage_account_keys({'account': self.account,
                                                      'verbose': False})['storage_service_keys']['primary']
            self.container = self.get_params(key='container', params=arg, default=self.default_storage_container)
            self.blobtype = self.get_params(key='blobtype', params=arg, default=self.default_blobtype)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)
           
            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:                
                blob_service = BlobService(self.account, self.key)                
                with open(self.blob) as f:
                    if self.blobtype == 'page':
                        result = blob_service.put_page_blob_from_file(self.container,
                                                                      self.blob,
                                                                      f,
                                                                      count=self.disk_size,
                                                                      max_connections=4,
                                                                      progress_callback=None)                        
                    if self.blobtype == 'block':
                        result = blob_service.put_block_blob_from_file(self.container,
                                                                       self.blob,
                                                                       f,
                                                                       count=self.disk_size,
                                                                       max_connections=4,
                                                                       progress_callback=None)                    
                return result
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def add_os_image(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.name = self.get_params(key='name', params=arg, default=None)
            if isinstance(self.name, list): self.name = self.name[0]
            self.label = self.get_params(key='label', params=arg, default=self.name)
            self.blob = self.get_params(key='blob', params=arg, default=None)
            if isinstance(self.blob, list): self.blob = self.blob[0]
            self.os = self.get_params(key='os', params=arg, default=None)
            self.account = self.get_params(key='account', params=arg, default=self.default_storage_account)
            self.container = self.get_params(key='container', params=arg, default='images')       
            self.async = self.get_params(key='async', params=arg, default=None)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)

            self.media_link = 'https://%s.blob.core.windows.net/%s/%s' % (self.account,
                                                                          self.container,
                                                                          self.blob)
            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                try:
                    result = self.sms.add_os_image(self.label, self.media_link, self.name, self.os)
                    d = dict()
                    operation = self.sms.get_operation_status(result.request_id)
                    d['result'] = result.__dict__
                    d['operation'] = operation.__dict__
                    if not self.async:
                        d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                        return d
                    else:
                        return d
                except (WindowsAzureConflictError) as e:
                    logger('%s: operation in progress or resource exists, try again..' % inspect.stack()[0][3])
                    return False
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
    
    def add_service_certificate(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False
            
            self.service = self.get_params(key='service', params=arg, default=None)
            self.certificate = self.get_params(key='certificate', params=arg, default=self.default_certificate)
            self.password = self.get_params(key='password', params=arg, default=None)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            self.async = self.get_params(key='async', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)

            with open(self.certificate, 'rb') as cf:
                self.cert_data = b64encode(cf.read())

            cert_fname, cert_ext = os.path.splitext(self.certificate)
            cert_ext = cert_ext.replace('.', '')
            if cert_ext == 'pfx':
                if not self.password:
                    logger('%s: certificate format %s requires password' % (inspect.stack()[0][3], cert_ext))
                    sys.exit(1)
            elif cert_ext == 'cer':
                # http://stackoverflow.com/questions/18117578/azure-add-certificate-to-cloudservice                
                self.password = ''
            else:
                logger('%s: certificate format %s not supported' % (inspect.stack()[0][3], cert_ext))
                sys.exit(1)

            cert_format = 'pfx'

            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                result = self.sms.add_service_certificate(self.service, self.cert_data,
                                                          cert_format, self.password)
                if result is not None:
                        d = dict()
                        operation = self.sms.get_operation_status(result.request_id)
                        d['result'] = result.__dict__
                        d['operation'] = operation.__dict__
                        if not self.async:
                            d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                            return d
                        else:
                            return d
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def build_epacls_dict_from_xml(self, **kwargs):
        try:
            if not kwargs: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=kwargs)
            if not arg: return False
            
            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.name = self.get_params(key='name', params=arg, default=None)
            if isinstance(self.name, list): self.name = self.name[0]
            
            xml = self.get_epacls(self.__dict__)['result']['body']            
            d = xmltodict.parse(xml)['PersistentVMRole']['ConfigurationSets']['ConfigurationSet']['InputEndpoints']
            epl = []
            for k, v in d.iteritems():                
                if not isinstance(v, list): v = [v]
                epd = dict()                
                for epacl in v:
                    epd = {'LocalPort': epacl['LocalPort'],
                           'Name': epacl['Name'],
                           'Port': epacl['Port'],
                           'Protocol': epacl['Protocol'],
                           'EnableDirectServerReturn': epacl['EnableDirectServerReturn']}
                    if 'EndpointAcl' in epacl:
                        for kk, vv in epacl['EndpointAcl']['Rules'].iteritems():
                            acl = []
                            for rule in vv:
                                acl.append((rule['Description'], rule['RemoteSubnet'], rule['Action'], rule['Order']))
                            epd['acls'] = acl
                    epl.append(epd)
            return epl
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
        
    def build_resource_extensions_xml_from_dict(self, **kwargs):
        try:
            if not kwargs: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=kwargs)
            if not arg: return False

            self.extensions = self.get_params(key='extensions', params=arg, default=None)
   
            rers = ResourceExtensionReferences()
            for ext in self.extensions:
                rer = ResourceExtensionReference()
                rer.reference_name = ext['Name']
                rer.publisher = ext['Publisher']
                rer.name = ext['Name']
                rer.version = ext['Version']
                repvs = ResourceExtensionParameterValues()
                for param in ext['Parameters']:
                    repv = ResourceExtensionParameterValue()
                    repv.key = param['Key']
                    repv.type = param['Type']
                    repv.value = param['Value']
                    repvs.resource_extension_parameter_values.append(repv)
                rer.resource_extension_parameter_values = repvs
                rer.state = ext['State']
                rers.resource_extension_references.append(rer)
            rextrs = rers
            return rextrs
        except Exception as e:
            logger(message=traceback.print_exc())
            return False 

    def build_resource_extension_dict(self, **kwargs):
        try:
            if not kwargs: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=kwargs)
            if not arg: return False

            self.os = self.get_params(key='os', params=arg, default=None)
            self.extension = self.get_params(key='extension', params=arg, default=self.default_extension)
            self.publisher = self.get_params(key='publisher', params=arg, default=self.default_publisher)
            self.version = self.get_params(key='version', params=arg, default=None)

            pub_config_key = self.get_params(key='pub_config_key', params=arg, default=None)
            pri_config_key = self.get_params(key='pri_config_key', params=arg, default=None)
            pub_config = self.get_params(key='pub_config', params=arg, default=None)
            pri_config = self.get_params(key='pri_config', params=arg, default=None)
            
            rext = {self.os: [{'Name': self.extension,
                               'ReferenceName': self.extension,
                               'Publisher': self.publisher,
                               'Version': self.version,
                               'State': 'Enable',
                               'Parameters': []}]}
            if pub_config and pub_config_key:
                if isinstance(pub_config, dict):
                    pub_config = b64encode(json.dumps(pub_config))
                else:
                    pub_config = b64encode(pub_config)                
                rext[self.os][0]['Parameters'].append({'Key': pub_config_key,
                                                       'Type': 'Public',
                                                       'Value': pub_config})                

            if pri_config and pri_config_key:
                if isinstance(pri_config, dict):
                    pri_config = b64encode(json.dumps(pri_config))
                else:
                    pri_config = b64encode(pri_config)
                rext[self.os][0]['Parameters'].append({'Key': pri_config_key,
                                                       'Type': 'Private',
                                                       'Value': pri_config})                    
            return rext
        except Exception as e:
            logger(message=traceback.print_exc())
            return False        

    def build_chefclient_resource_extension(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.os = self.get_params(key='os', params=arg, default=None)            
            self.chef_server_url = self.get_params(key='chef_server_url', params=arg, default=self.default_chef_server_url)
            self.chef_validation_client_name = self.get_params(key='chef_validation_client_name', params=arg, default=self.default_chef_validation_client_name)
            self.chef_validation_key_file = self.get_params(key='chef_validation_key_file', params=arg, default=self.default_chef_validation_key_file)
            self.chef_run_list = self.get_params(key='chef_run_list', params=arg, default=self.default_chef_validation_client_name)
            self.chef_autoupdate_client = self.get_params(key='chef_autoupdate_client', params=arg, default=str(self.default_chef_autoupdate_client).lower())
            self.chef_delete_config = self.get_params(key='chef_delete_config', params=arg, default=str(self.default_chef_delete_config).lower())
            self.chef_ssl_verify_mode = self.get_params(key='chef_ssl_verify_mode', params=arg, default=self.default_chef_ssl_verify_mode)
            self.chef_verify_api_cert = self.get_params(key='chef_verify_api_cert', params=arg, default=str(self.default_chef_verify_api_cert).lower())

            pub_config = dict()
            pri_config = dict()
            pub_config_key = 'ChefClientPublicConfigParameter'
            pri_config_key = 'ChefClientPrivateConfigParameter'
            self.publisher = 'Chef.Bootstrap.WindowsAzure'
            pub_config = '{"runlist":\"%s\",' \
                         '"autoUpdateClient":"%s",' \
                         '"deleteChefConfig":"%s",' \
                         '"client_rb":"\nchef_server_url\t\\"%s\\"\n' \
                         'validation_client_name\t\\"%s\\"\n' \
                         'node_name\t\\"%s\\"\n' \
                         'ssl_verify_mode\t%s\n' \
                         'verify_api_cert\t%s"}' % (self.chef_run_list,
                                                    self.chef_autoupdate_client,
                                                    self.chef_delete_config,
                                                    self.chef_server_url,
                                                    self.chef_validation_client_name,
                                                    self.name,
                                                    self.chef_ssl_verify_mode,
                                                    self.chef_verify_api_cert)
            try:
                with open(self.chef_validation_key_file, 'rb') as f:
                    pri_config = '{"validation_key":"%s"}' % f.read()
            except IOError:
                pri_config['validation_key'] = None
                pass

            if self.os == 'Windows':
                self.extension = 'ChefClient'
                rexts = self.list_resource_extension_versions({'publisher': self.publisher, 'extension': self.extension, 'verbose': False})
                version = None
                for rext in rexts:
                    version = rext['version']                
                self.version = version.split('.')[0] + '.*'
                rext = self.build_resource_extension_dict(os=self.os, extension=self.extension, publisher=self.publisher, version=self.version,
                                                          pub_config_key=pub_config_key, pri_config_key=pub_config_key,
                                                          pub_config=pub_config, pri_config=pri_config)
            if self.os == 'Linux':
                self.extension = 'LinuxChefClient'
                rexts = self.list_resource_extension_versions({'publisher': self.publisher, 'extension': self.extension, 'verbose': False})
                version = None
                for rext in rexts:
                    version = rext['version']
                self.version = version.split('.')[0] + '.*'
                rext = self.build_resource_extension_dict(os=self.os, extension=self.extension, publisher=self.publisher, version=self.version,
                                                          pub_config_key=pub_config_key, pri_config_key=pub_config_key,
                                                          pub_config=pub_config, pri_config=pri_config)
            return self.build_resource_extensions_xml_from_dict(extensions=rext[self.os])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False             

    def build_customscript_resource_extension(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.os = self.get_params(key='os', params=arg, default=None)            
            self.account = self.get_params(key='account', params=arg, default=self.default_storage_account)            
            self.container = self.get_params(key='container', params=arg, default=self.default_storage_container)
                   
            pub_config = dict()
            pub_config_key = 'CustomScriptExtensionPublicConfigParameter'
            if self.os == 'Windows':                
                self.script = self.get_params(key='script', params=arg, default=self.default_windows_customscript_name)
                result = self.upload_blob({'blob': self.script, 'account': self.account,
                                           'blobtype': 'block', 'verbose': True})
                pprint.pprint(result)
                pub_config['fileUris'] = ['%s' % self.generate_signed_blob_url(account=self.account,
                                                                               container=self.container,
                                                                               script=self.script)]
                self.extension = 'CustomScriptExtension'
                self.publisher = 'Microsoft.Compute'
                rexts = self.list_resource_extension_versions({'publisher': self.publisher, 'extension': self.extension, 'verbose': False})
                version = None
                for rext in rexts:
                    version = rext['version']                
                self.version = version.split('.')[0] + '.*'
                pub_config['commandToExecute'] = 'powershell.exe -ExecutionPolicy Unrestricted -File %s' % self.script
                pub_config['timestamp'] = '%s' % timegm(time.gmtime())                    
                rext = self.build_resource_extension_dict(os=self.os, extension=self.extension, publisher=self.publisher, version=self.version,
                                                          pub_config_key=pub_config_key, pub_config=pub_config)
            if self.os == 'Linux':
                pri_config_key = 'CustomScriptExtensionPrivateConfigParameter'
                pri_config = dict()
                self.script = self.get_params(key='script', params=arg, default=self.default_linux_customscript_name)
                result = self.upload_blob({'blob': self.script, 'account': self.account,
                                           'blobtype': 'block', 'verbose': True})
                pprint.pprint(result)
                self.extension = 'CustomScriptForLinux'
                self.publisher = 'Microsoft.OSTCExtensions'
                rexts = self.list_resource_extension_versions({'publisher': self.publisher, 'extension': self.extension, 'verbose': False})
                version = None
                for rext in rexts:
                    version = rext['version']          
                self.version = version.split('.')[0] + '.*' 
                pub_config['fileUris'] = ['%s' % self.generate_signed_blob_url(account=self.account,
                                                                               container=self.container,
                                                                               script=self.script)]               
                pub_config['commandToExecute'] = './%s' % self.script
                pub_config['timestamp'] = '%s' % timegm(time.gmtime())
                pri_config['storageAccountName'] = self.account
                pri_config['storageAccountKey'] = self.get_storage_account_keys({'account': self.account,
                                                                                 'verbose': False})['storage_service_keys']['primary']                
                rext = self.build_resource_extension_dict(os=self.os, extension=self.extension, publisher=self.publisher, version=self.version,
                                                          pub_config_key=pub_config_key, pub_config=pub_config,
                                                          pri_config_key=pri_config_key, pri_config=pri_config)
                
            return self.build_resource_extensions_xml_from_dict(extensions=rext[self.os])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def build_vmaccess_resource_extension(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.os = self.get_params(key='os', params=arg, default=None)
            self.username = self.get_params(key='username', params=arg, default=self.default_user_name)
            self.password = self.get_params(key='password', params=arg, default=None)
            self.vmaop = self.get_params(key='vmaop', params=arg, default=self.default_vmaop)
            self.certificate = self.get_params(key='certificate', params=arg, default=self.default_certificate)
            self.algorithm = self.get_params(key='algorithm', params=arg, default=self.default_algorithm)
            self.pwd_expiry = self.get_params(key='pwd_expiry', params=arg, default=self.default_pwd_expiry)

            pub_config = dict()
            pri_config = dict() 
            if self.os == 'Windows':                   
                pub_config_key = 'VMAccessAgentPublicConfigParameter'
                pri_config_key = 'VMAccessAgentPrivateConfigParameter'
                self.extension = 'VMAccessAgent'
                self.publisher = 'Microsoft.Compute'
                rexts = self.list_resource_extension_versions({'publisher': self.publisher, 'extension': self.extension, 'verbose': False})
                version = None
                for rext in rexts:
                    version = rext['version']          
                self.version = version.split('.')[0] + '.*'
                pub_config['timestamp'] = '%s' % timegm(time.gmtime())

                if self.vmaop == 'ResetRDPConfig':
                    pass                    

                elif self.vmaop == 'ResetPassword':
                    if self.password:
                        pub_config['UserName'] = self.username
                        pri_config['Password'] = self.password
                        pri_config['expiration'] = mkdate(datetime.now() + timedelta(days=self.pwd_expiry), '%Y-%m-%d')
                    else:                            
                        logger(pprint.pprint(self.__dict__))
                        logger('VMAccess operation %s requires a new password' % self.vmaop)
                        sys.exit(1)
                else:
                    logger(pprint.pprint(self.__dict__))
                    logger('%s is not a supported VMAccess operation' % self.vmaop)
                    sys.exit(1)
                rext = self.build_resource_extension_dict(os=self.os, extension=self.extension, publisher=self.publisher, version=self.version,
                                                          pub_config_key=pub_config_key, pub_config=pub_config,
                                                          pri_config_key=pri_config_key, pri_config=pri_config)
            
            if self.os == 'Linux':
                pub_config_key = 'VMAccessForLinuxPublicConfigParameter'
                pri_config_key = 'VMAccessForLinuxPrivateConfigParameter'
                self.extension = 'VMAccessForLinux'
                self.publisher = 'Microsoft.OSTCExtensions'
                rexts = self.list_resource_extension_versions({'publisher': self.publisher, 'extension': self.extension, 'verbose': False})
                version = None
                for rext in rexts:
                    version = rext['version']          
                self.version = version.split('.')[0] + '.*'
                pub_config['timestamp'] = '%s' % timegm(time.gmtime())

                result = self.get_pub_key_and_thumbprint_from_x509_cert(certificate=self.certificate, algorithm=self.algorithm)
                self.public_key = result['public_key']
                   
                if self.vmaop == 'ResetSSHKey':
                    pri_config['username'] = self.username
                    pri_config['ssh_key'] = self.public_key
                elif self.vmaop == 'ResetPassword':
                    if self.password:
                        pri_config['username'] = self.username
                        pri_config['password'] = self.password
                        pri_config['expiration'] = mkdate(datetime.now() + timedelta(days=self.pwd_expiry), '%Y-%m-%d')
                    else:                            
                        logger(pprint.pprint(self.__dict__))
                        logger('VMAccess operation %s requires a new password' % self.vmaop)
                        sys.exit(1)
                elif self.vmaop == 'ResetSSHKeyAndPassword':
                    if self.password:
                        pri_config['username'] = self.username
                        pri_config['password'] = self.password
                        pri_config['ssh_key'] = self.public_key
                    else:                            
                        logger(pprint.pprint(self.__dict__))
                        logger('VMAccess operation %s requires a new password' % self.vmaop)
                        sys.exit(1)
                elif self.vmaop == 'DeleteUser':
                    pri_config['remove_user'] = self.username
                elif self.vmaop == 'ResetSSHConfig':
                    pri_config['reset_ssh'] = True
                else:
                    logger(pprint.pprint(self.__dict__))
                    logger('%s is not a supported VMAccess operation' % self.vmaop)
                    sys.exit(1)
                    
                rext = self.build_resource_extension_dict(os=self.os, extension=self.extension, publisher=self.publisher, version=self.version,
                                                          pri_config_key=pri_config_key, pri_config=pri_config)
            return self.build_resource_extensions_xml_from_dict(extensions=rext[self.os])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def build_ospatching_resource_extension(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.os = self.get_params(key='os', params=arg, default=None)
            self.account = self.get_params(key='account', params=arg, default=self.default_storage_account)
            self.patching_disabled = self.get_params(key='patching_disabled', params=arg, default=False)
            self.patching_stop = self.get_params(key='patching_stop', params=arg, default=False)
            self.patching_local = self.get_params(key='patching_local', params=arg, default=False)
            self.patching_oneoff = self.get_params(key='patching_oneoff', params=arg, default=False)
            self.patching_reboot_after = self.get_params(key='patching_reboot_after', params=arg, default=self.default_patching_reboot_after)
            self.patching_interval = self.get_params(key='patching_interval', params=arg, default=self.default_patching_interval)
            self.patching_day = self.get_params(key='patching_day', params=arg, default=self.default_patching_day)
            self.patching_starttime = self.get_params(key='patching_starttime', params=arg, default=self.default_patching_starttime)
            self.patching_category = self.get_params(key='patching_category', params=arg, default=self.default_patching_category)
            self.patching_duration = self.get_params(key='patching_duration', params=arg, default=self.default_patching_duration)
            self.patching_healthy_test_script = self.get_params(key='patching_healthy_test_script', params=arg, default=self.default_patching_healthy_test_script)
            self.patching_idle_test_script = self.get_params(key='patching_idle_test_script', params=arg, default=self.default_patching_idle_test_script)

            if self.os == 'Windows':
                logger(pprint.pprint(self.__dict__))
                logger('%s is not supported in Windows' % inspect.stack()[0][3])
                sys.exit(1)
            
            if self.os == 'Linux':
                pub_config = dict()
                pri_config = dict() 
                pub_config_key = 'OSPatchingForLinuxPublicConfigParameter'                   
                pri_config_key = 'OSPatchingForLinuxPrivateConfigParameter'
                self.extension = 'OSPatchingForLinux'
                self.publisher = 'Microsoft.OSTCExtensions'
                rexts = self.list_resource_extension_versions({'publisher': self.publisher, 'extension': self.extension, 'verbose': False})
                version = None
                for rext in rexts:
                    version = rext['version']          
                self.version = version.split('.')[0] + '.*'
                pub_config['timestamp'] = '%s' % timegm(time.gmtime())
                pub_config['disabled'] = self.patching_disabled
                pub_config['stop'] = self.patching_stop
                pub_config['rebootAfterPatch'] = self.patching_reboot_after
                pub_config['intervalOfWeeks'] = self.patching_interval
                pub_config['dayOfWeek'] = self.patching_day
                pub_config['startTime'] = self.patching_starttime
                pub_config['category'] = self.patching_category
                pub_config['installDuration'] = self.patching_duration
                pub_config['idleTestScript'] = self.patching_idle_test_script
                pub_config['healthyTestScript'] = self.patching_healthy_test_script
                pub_config['vmStatusTest'] = {'local': self.patching_local,
                                              'idleTestScript': self.patching_idle_test_script,
                                              'healthyTestScript': self.patching_healthy_test_script}
                pub_config['oneoff'] = self.patching_oneoff
                pri_config['storageAccountName'] = self.account
                pri_config['storageAccountKey'] = self.get_storage_account_keys({'account': self.account,
                                                                                 'verbose': False})['storage_service_keys']['primary']
                rext = self.build_resource_extension_dict(os=self.os, extension=self.extension, publisher=self.publisher, version=self.version,
                                                          pub_config_key=pub_config_key, pub_config=pub_config,
                                                          pri_config_key=pri_config_key, pri_config=pri_config)
            return self.build_resource_extensions_xml_from_dict(extensions=rext[self.os])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def build_dsc_resource_extension(self):
        pass

    def build_docker_resource_extension(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.os = self.get_params(key='os', params=arg, default=None)
            self.docker_registry_server = self.get_params(key='docker_registry_server', params=arg, default=None)
            self.docker_username = self.get_params(key='docker_username', params=arg, default=self.default_docker_username)
            self.docker_password = self.get_params(key='docker_password', params=arg, default=self.default_docker_password)
            self.docker_email = self.get_params(key='docker_email', params=arg, default=self.default_docker_email)
            self.docker_options = self.get_params(key='docker_options', params=arg, default=self.default_docker_options)
            self.docker_options = self.docker_options.split(',')
            self.docker_port = self.get_params(key='docker_port', params=arg, default=self.default_docker_port)
            self.docker_ca_certificate = self.get_params(key='docker_ca_certificate', params=arg, default=self.default_docker_ca_certificate)
            self.docker_server_certificate = self.get_params(key='docker_server_certificate', params=arg, default=self.default_docker_server_certificate)
            self.docker_server_key = self.get_params(key='docker_server_key', params=arg, default=self.default_docker_server_key)

            pub_config = dict()
            pri_config = dict() 
            if self.os == 'Windows':                   
                logger(pprint.pprint(self.__dict__))
                logger('%s is not supported in Windows' % inspect.stack()[0][3])
                sys.exit(1)                
            
            if self.os == 'Linux':
                pub_config_key = 'DockerExtensionPublicConfigParameter'
                pri_config_key = 'DockerExtensionPrivateConfigParameter'
                self.extension = 'DockerExtension'
                self.publisher = 'Microsoft.Azure.Extensions'
                rexts = self.list_resource_extension_versions({'publisher': self.publisher, 'extension': self.extension, 'verbose': False})
                version = None
                for rext in rexts:
                    version = rext['version']          
                self.version = version.split('.')[0] + '.*'
                pub_config['timestamp'] = '%s' % timegm(time.gmtime())
                pub_config['docker'] = dict()
                pub_config['docker']['port'] = self.docker_port
                pub_config['docker']['options'] = self.docker_options
                pri_config['certs'] = dict()
                pri_config['compose'] = dict()

                try:
                    with open(self.docker_ca_certificate, 'rb') as cf:
                        docker_ca_certificate = b64encode(cf.read())
                except IOError:
                    logger('%s: unable to read %s' % (inspect.stack()[0][3], self.docker_ca_certificate))
                    sys.exit(1)
                
                pri_config['certs']['ca'] = docker_ca_certificate

                try:
                    with open(self.docker_server_certificate, 'rb') as cf:
                        docker_server_certificate = b64encode(cf.read())
                except IOError:
                    logger('%s: unable to read %s' % (inspect.stack()[0][3], self.docker_server_certificate))
                    sys.exit(1)
                
                pri_config['certs']['cert'] = docker_server_certificate

                try:
                    with open(self.docker_server_key, 'rb') as cf:
                        docker_server_key = b64encode(cf.read())
                except IOError:
                    logger('%s: unable to read %s' % (inspect.stack()[0][3], self.docker_server_key))
                    sys.exit(1)
                
                pri_config['certs']['key'] = docker_server_key
                
                pri_config['login'] = dict()
                pri_config['login']['server'] = self.docker_registry_server
                pri_config['login']['username'] = self.docker_username
                pri_config['login']['password'] = self.docker_password
                pri_config['login']['email'] = self.docker_email
                    
                rext = self.build_resource_extension_dict(os=self.os, extension=self.extension, publisher=self.publisher, version=self.version,
                                                          pri_config_key=pri_config_key, pri_config=pri_config)
            return self.build_resource_extensions_xml_from_dict(extensions=rext[self.os])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
    
    def build_octopusdeploy_resource_extension(self):
        pass
   
    def build_puppet_resource_extension(self):
        pass

    def build_logcollector_resource_extension(self):
        pass
    
    def build_vsreleasemanager_resource_extension(self):
        pass
    
    def build_vsremotedebug_resource_extension(self):
        pass
   
    def build_bginfo_resource_extension(self):
        pass
    
    def build_monitoringagent_resource_extension(self):
        pass
    
    def build_sqlagent_resource_extension(self):
        pass
    
    def build_antimalware_resource_extension(self):
        pass
    
    def cert_file(self):
        return self.sms.cert_file
    
    def content_type(self):
        return self.sms.content_type

    def check_hosted_service_name_availability(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.service = self.get_params(key='service', params=arg, default=None)

            result = self.sms.check_hosted_service_name_availability(self.service)
            return result.__dict__
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
        
    def check_storage_account_name_availability(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.account = self.get_params(key='account', params=arg, default=self.default_storage_account)
            
            result = self.sms.check_storage_account_name_availability(self.account)
            return result.__dict__
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
        
    def create_affinity_group(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.name = self.get_params(key='name', params=arg, default=None)
            if isinstance(self.name, list): self.name = self.name[0]
            self.label = self.get_params(key='label', params=arg, default=self.name)
            self.description = self.get_params(key='description', params=arg, default=None)
            self.location = self.get_params(key='location', params=arg, default=self.default_location)
            self.async = self.get_params(key='async', params=arg, default=None)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)

            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                return self.sms.create_affinity_group(name=self.name, label=self.label,
                                                      location=self.location, description=self.description)
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def create_virtual_machine_deployment(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.name = self.get_params(key='name', params=arg, default=None)
            if isinstance(self.name, list): self.name = self.name[0]
            self.dns = self.get_params(key='dns', params=arg, default=None)
            if isinstance(self.dns, list): self.dns = self.dns[0]
            self.ipaddr = self.get_params(key='ipaddr', params=arg, default=None)
            if isinstance(self.ipaddr, list): self.ipaddr = self.ipaddr[0]
            self.os = self.get_params(key='os', params=arg, default=None)
            self.blob = self.get_params(key='blob', params=arg, default=None)
            if isinstance(self.blob, list): self.blob = self.blob[0]
            self.account = self.get_params(key='account', params=arg, default=None)
            self.network = self.get_params(key='network', params=arg, default=None)
            self.subnet = self.get_params(key='subnet', params=arg, default=None)
            if isinstance(self.subnet, list): self.subnet = self.subnet[0]
            self.container = self.get_params(key='container', params=arg, default=self.default_storage_container)
            self.label = self.get_params(key='label', params=arg, default=self.name)
            self.availset = self.get_params(key='availset', params=arg, default=None)
            self.password = self.get_params(key='password', params=arg, default=''.join(SystemRandom().choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for _ in range(11)))
            self.slot = self.get_params(key='slot', params=arg, default=self.default_deployment_slot)            
            self.size = self.get_params(key='size', params=arg, default=self.default_size)
            self.username = self.get_params(key='username', params=arg, default=self.default_user_name)        
            self.eps = self.get_params(key='eps', params=arg, default=self.default_endpoints)
            self.rextrs = self.get_params(key='rextrs', params=arg, default=None)
            self.certificate = self.get_params(key='certificate', params=arg, default=self.default_certificate)
            self.algorithm = self.get_params(key='algorithm', params=arg, default=self.default_algorithm)
            self.async = self.get_params(key='async', params=arg, default=None)    
            self.readonly = self.get_params(key='readonly', params=arg, default=None)                
            self.ssh_auth = self.get_params(key='ssh_auth', params=arg, default=None)                
            self.disable_pwd_auth = self.get_params(key='disable_pwd_auth', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)
 
            if self.os == 'Windows':
                self.custom_data_file = self.get_params(key='custom_data_file', params=arg, default=self.default_windows_custom_data_file)
                try:
                    self.custom_data = None                                                    
                    with open(self.custom_data_file, 'rb') as cf:
                        self.custom_data = b64encode(cf.read())
                except IOError:
                    logger('%s: unable to read %s' % (inspect.stack()[0][3], self.custom_data_file))
                    pass

            if self.os == 'Linux':
                self.custom_data_file = self.get_params(key='custom_data_file', params=arg, default=self.default_linux_custom_data_file)
                try:
                    self.custom_data = None                                                    
                    with open(self.custom_data_file, 'rb') as cf:
                        self.custom_data = cf.read()
                except IOError:
                    logger('%s: unable to read %s' % (inspect.stack()[0][3], self.custom_data_file))
                    pass                                                                        

            net_config = ConfigurationSet()
            net_config.configuration_set_type = 'NetworkConfiguration'
            subnet = Subnet()
            subnet.name = self.subnet           
            subnets = Subnets()
            subnets.subnets.append(subnet.name)
            net_config.subnet_names = subnets
           
            endpoints = []                        
            if self.os in ['Windows']:
                self.os_config = WindowsConfigurationSet(computer_name=self.name,
                                                         admin_password=self.password,
                                                         reset_password_on_first_logon=None,
                                                         enable_automatic_updates=None,
                                                         time_zone=None,
                                                         admin_username=self.username,
                                                         custom_data=self.custom_data)
                self.os_config.domain_join = None
                self.os_config.win_rm = None
                self.os_config.stored_certificate_settings = None
                self.os_config.additional_unattend_content = None

                for ep in self.eps[self.os]:
                    endpoints.append(ConfigurationSetInputEndpoint(name=ep['Name'],
                                                                   protocol=ep['Protocol'],
                                                                   port=ep['Port'],
                                                                   local_port=ep['LocalPort'],
                                                                   load_balanced_endpoint_set_name=None,
                                                                   enable_direct_server_return=False))                    
                for endpoint in endpoints:
                    net_config.input_endpoints.input_endpoints.append(endpoint)

            endpoints = []                
            if self.os in ['Linux']:
                if self.disable_pwd_auth:
                    self.password = None
                    self.ssh_auth = True
                    
                self.os_config = LinuxConfigurationSet(host_name=self.name,
                                                       user_name=self.username,
                                                       user_password=self.password,
                                                       disable_ssh_password_authentication=self.ssh_auth,
                                                       custom_data=self.custom_data)                    
                if self.ssh_auth:
                    ssh = SSH()
                    pks = PublicKeys()
                    pk = PublicKey()
                    pk.path = '/home/%s/.ssh/authorized_keys' % self.username

                    result = self.get_pub_key_and_thumbprint_from_x509_cert(certificate=self.certificate, algorithm=self.algorithm)
                    self.thumbprint = result['thumbprint']
                    pk.fingerprint = self.thumbprint
                   
                    pks.public_keys.append(pk)
                    ssh.public_keys = pks
                    self.os_config.ssh = ssh

                for ep in self.eps[self.os]:
                    endpoints.append(ConfigurationSetInputEndpoint(name=ep['Name'],
                                                                   protocol=ep['Protocol'],
                                                                   port=ep['Port'],
                                                                   local_port=ep['LocalPort'],
                                                                   load_balanced_endpoint_set_name=None,
                                                                   enable_direct_server_return=False))
                for endpoint in endpoints:
                    net_config.input_endpoints.input_endpoints.append(endpoint)
                
            self.net_config = net_config            
            ts = mkdate(datetime.now(), '%Y-%m-%d-%H-%M-%S-%f')            
            self.media_link = 'https://%s.blob.core.windows.net/%s/%s-%s-%s-0.vhd' % (self.account,
                                                                                      self.container,
                                                                                      self.service,
                                                                                      self.name,
                                                                                      ts)
            self.disk_config = OSVirtualHardDisk(source_image_name=self.blob,
                                                 media_link=self.media_link,
                                                 host_caching=None,
                                                 disk_label=None,
                                                 disk_name=None,
                                                 os=None,
                                                 remote_source_image_link=None)
            
            if verbose: pprint.pprint(self.__dict__)            

            if not self.readonly:
                try:
                    d = dict()
                    result = self.sms.create_virtual_machine_deployment(self.service, self.deployment, self.slot,
                                                                        self.label, self.name,
                                                                        self.os_config, self.disk_config,
                                                                        network_config=self.net_config,
                                                                        availability_set_name=self.availset,
                                                                        data_virtual_hard_disks=None,
                                                                        role_size=self.size,
                                                                        role_type='PersistentVMRole',
                                                                        virtual_network_name=self.network,
                                                                        resource_extension_references=self.rextrs,
                                                                        provision_guest_agent=True,
                                                                        vm_image_name=None,
                                                                        media_location=None,
                                                                        dns_servers=self.dns,
                                                                        reserved_ip_name=self.ipaddr)
                    d['result'] = result.__dict__
                    if not self.async:
                        operation = self.sms.get_operation_status(result.request_id)
                        d['operation'] = operation.__dict__
                        d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                        self.wait_for_vm_provisioning_completion({'service': self.service,
                                                                  'deployment': self.deployment,
                                                                  'name': self.name})
                        return d
                    else:
                        return 
                except (WindowsAzureConflictError) as e:
                    logger('%s: operation in progress or resource exists, try again..' % inspect.stack()[0][3])
                    return False
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def capture_role(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.name = self.get_params(key='name', params=arg, default=None)
            if isinstance(self.name, list): self.name = self.name[0]
            self.post_capture_action = self.get_params(key='post_capture_action', params=arg, default=self.default_post_capture_action)
            self.blob = self.get_params(key='blob', params=arg, default=None)
            if isinstance(self.blob, list): self.blob = self.blob[0]
            self.label = self.get_params(key='label', params=arg, default=self.blob)
            self.os = self.get_params(key='os', params=arg, default=self.get_role({'service': self.service,
                                                                                   'deployment': self.deployment,
                                                                                   'name': self.name,
                                                                                   'verbose': False})['os_virtual_hard_disk']['os'])
            self.password = self.get_params(key='password', params=arg, default=''.join(SystemRandom().choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for _ in range(11)))
            self.username = self.get_params(key='username', params=arg, default=self.default_user_name)        
            self.certificate = self.get_params(key='certificate', params=arg, default=self.default_certificate)
            self.algorithm = self.get_params(key='algorithm', params=arg, default=self.default_algorithm)
            self.ssh_auth = self.get_params(key='ssh_auth', params=arg, default=None)                
            self.disable_pwd_auth = self.get_params(key='disable_pwd_auth', params=arg, default=None)
            self.async = self.get_params(key='async', params=arg, default=None)    
            self.readonly = self.get_params(key='readonly', params=arg, default=None)                
            verbose = self.get_params(key='verbose', params=arg, default=None)
 
            if self.os == 'Windows':
                self.custom_data_file = self.get_params(key='custom_data_file', params=arg, default=self.default_windows_custom_data_file)
                try:
                    self.custom_data = None                                                    
                    with open(self.custom_data_file, 'rb') as cf:
                        self.custom_data = b64encode(cf.read())
                except IOError:
                    logger('%s: unable to read %s' % (inspect.stack()[0][3], self.custom_data_file))
                    pass

            if self.os == 'Linux':
                self.custom_data_file = self.get_params(key='custom_data_file', params=arg, default=self.default_linux_custom_data_file)
                try:
                    self.custom_data = None                                                    
                    with open(self.custom_data_file, 'rb') as cf:
                        self.custom_data = cf.read()
                except IOError:
                    logger('%s: unable to read %s' % (inspect.stack()[0][3], self.custom_data_file))
                    pass                                                                        

            if self.os == 'Windows':
                self.os_config = WindowsConfigurationSet(computer_name=self.name,
                                                         admin_password=self.password,
                                                         reset_password_on_first_logon=None,
                                                         enable_automatic_updates=None,
                                                         time_zone=None,
                                                         admin_username=self.username,                                                         
                                                         custom_data=self.custom_data)
                self.os_config.domain_join = None
                self.os_config.win_rm = None
                self.os_config.stored_certificate_settings = None
                self.os_config.additional_unattend_content = None

            if self.os == 'Linux':
                if self.disable_pwd_auth:
                    self.password = None
                    self.ssh_auth = True
                    
                self.os_config = LinuxConfigurationSet(host_name=self.name,
                                                       user_name=self.username,
                                                       user_password=self.password,
                                                       disable_ssh_password_authentication=self.ssh_auth,
                                                       custom_data=self.custom_data)                    
                if self.ssh_auth:
                    ssh = SSH()
                    pks = PublicKeys()
                    pk = PublicKey()
                    pk.path = '/home/%s/.ssh/authorized_keys' % self.username

                    result = self.get_pub_key_and_thumbprint_from_x509_cert(certificate=self.certificate,
                                                                            algorithm=self.algorithm)
                    self.thumbprint = result['thumbprint']
                    pk.fingerprint = self.thumbprint
                   
                    pks.public_keys.append(pk)
                    ssh.public_keys = pks
                    self.os_config.ssh = ssh
                
            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                try:
                    d = dict()                    
                    result = self.sms.capture_role(self.service, self.deployment, self.name,
                                                   self.post_capture_action, self.blob, self.label,
                                                   provisioning_configuration=self.os_config)
                    d['result'] = result.__dict__
                    if not self.async:
                        operation = self.sms.get_operation_status(result.request_id)
                        d['operation'] = operation.__dict__
                        d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                        return d
                    else:
                        return 
                except (WindowsAzureConflictError) as e:
                    logger('%s: operation in progress or resource exists, try again..' % inspect.stack()[0][3])
                    return False
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
    
    def capture_vm_image(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.name = self.get_params(key='name', params=arg, default=None)
            if isinstance(self.name, list): self.name = self.name[0]
            self.blob = self.get_params(key='blob', params=arg, default=None)
            if isinstance(self.blob, list): self.blob = self.blob[0]
            self.label = self.get_params(key='label', params=arg, default=self.blob)
            self.description = self.get_params(key='label', params=arg, default=self.label)
            self.os_state = self.get_params(key='os_state', params=arg, default=self.default_os_state)
            self.language = self.get_params(key='language', params=arg, default=None)
            self.family = self.get_params(key='family', params=arg, default=None)
            self.size = self.get_params(key='size', params=arg, default=self.default_size)            
            self.async = self.get_params(key='async', params=arg, default=None)    
            self.readonly = self.get_params(key='readonly', params=arg, default=None)                
            verbose = self.get_params(key='verbose', params=arg, default=None)

            options = CaptureRoleAsVMImage()
            options.os_state = self.os_state
            options.vm_image_name = self.blob
            options.vm_image_label = self.label
            options.description = self.description
            options.language = self.language
            options.image_family = self.family
            options.recommended_vm_size =self.size
            self.options = options

            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                try:
                    d = dict()                    
                    result = self.sms.capture_vm_image(self.service, self.deployment, self.name, self.options)
                    d['result'] = result.__dict__
                    if not self.async:
                        operation = self.sms.get_operation_status(result.request_id)
                        d['operation'] = operation.__dict__
                        d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                        return d
                    else:
                        return 
                except (WindowsAzureConflictError) as e:
                    logger('%s: operation in progress or resource exists, try again..' % inspect.stack()[0][3])
                    return False
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
        
    def create_deployment(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.slot = self.get_params(key='service', params=arg, default=None)
            self.name = self.get_params(key='name', params=arg, default=None)
            if isinstance(self.name, list): self.name = self.name[0]
            self.label = self.get_params(key='label', params=arg, default=self.name)
            self.package_url = self.get_params(key='package_url', params=arg, default=None)
            self.package_config = self.get_params(key='package_config', params=arg, default=None)
            self.account = self.get_params(key='account', params=arg, default=self.default_storage_account)            
            self.extended_properties = self.get_params(key='extended_properties', params=arg,
                                                       default=self.get_storage_account_properties({'account': self.account,
                                                                                                    'verbose': False})['extended_properties'])
            self.start_deployment = self.get_params(key='start_deployment', params=arg, default=self.default_start_deployment)
            self.ignore_warinings = self.get_params(key='ignore_warinings', params=arg, default=self.default_ignore_warinings)
            self.async = self.get_params(key='async', params=arg, default=None)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)
            
            try:
                self.package_config = None                                                    
                with open(self.package_config, 'rb') as cf:
                    self.configuration = b64encode(cf.read())
            except IOError:
                logger('%s: unable to read %s' % (inspect.stack()[0][3], self.package_config))
                pass

            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                try:
                    d = dict()
                    result = self.sms.create_deployment(self.service, self.slot, self.name,
                                                        self.package_url, self.label, self.configuration,
                                                        start_deployment=self.start_deployment,
                                                        treat_warnings_as_error=self.ignore_warinings,
                                                        extended_properties=self.extended_properties)
                    d['result'] = result.__dict__
                    if not self.async:
                        operation = self.sms.get_operation_status(result.request_id)
                        d['operation'] = operation.__dict__
                        d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                        return d
                    else:
                        return 
                except (WindowsAzureConflictError) as e:
                    logger('%s: operation in progress or resource exists, try again..' % inspect.stack()[0][3])
                    return False
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def xml_networkconfig_fragment_from_dict(self, **kwargs):
        try:
            if not kwargs: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=kwargs)
            if not arg: return False

            self.dns = self.get_params(key='dns', params=arg, default=None)
            self.ipaddr = self.get_params(key='ipaddr', params=arg, default=None)
            self.group = self.get_params(key='group', params=arg, default=None)
            self.network = self.get_params(key='network', params=arg, default=None)
            self.location = self.get_params(key='location', params=arg, default=self.default_location)
            self.subnet = self.get_params(key='subnet', params=arg, default=None)
            self.subnetaddr = self.get_params(key='subnetaddr', params=arg, default=None)
            self.vnetaddr = self.get_params(key='vnetaddr', params=arg, default=None)
            
            root = Element('NetworkConfiguration')
            root.set('xmlns', 'http://schemas.microsoft.com/ServiceHosting/2011/07/NetworkConfiguration')
            vnetconfig = SubElement(root, 'VirtualNetworkConfiguration')
            dns = SubElement(vnetconfig, 'Dns')
            dnsservers = SubElement(dns, 'DnsServers')
            for name, ipaddr in zip(self.dns, self.ipaddr):
                dnsserver = SubElement(dnsservers, 'DnsServer')
                dnsserver.set('name', name)
                dnsserver.set('IPAddress', ipaddr)
            vnetsites = SubElement(vnetconfig, 'VirtualNetworkSites')
            vnetsite = SubElement(vnetsites, 'VirtualNetworkSite')
            vnetsite.set('name', self.network)
            if self.group:
                vnetsite.set('AffinityGroup', self.group)
            else:
                vnetsite.set('Location', self.location)                
            dnsserversref = SubElement(vnetsite, 'DnsServersRef')
            for name in self.dns:
                dnsserverref = SubElement(dnsserversref, 'DnsServerRef')
                dnsserverref.set('name', name)
            subnets = SubElement(vnetsite, 'Subnets')
            for name, addr in zip(self.subnet, self.subnetaddr):
                subnet = SubElement(subnets, 'Subnet')
                subnet.set('name', name)
                addressprefix = SubElement(subnet, 'AddressPrefix')
                addressprefix.text = addr
            addressspace = SubElement(vnetsite, 'AddressSpace')
            for addr in self.vnetaddr:
                addressprefix = SubElement(addressspace, 'AddressPrefix')
                addressprefix.text = addr                
            return tostring(root)
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def create_virtual_network_site(self, *args):
        # https://msdn.microsoft.com/en-us/library/azure/jj157182.aspx
        # https://github.com/Azure/azure-sdk-for-python/issues/155

        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.dns = self.get_params(key='dns', params=arg, default=None)
            self.ipaddr = self.get_params(key='ipaddr', params=arg, default=None)
            self.group = self.get_params(key='group', params=arg, default=None)
            self.network = self.get_params(key='network', params=arg, default=None)
            self.location = self.get_params(key='location', params=arg, default=self.default_location)
            self.subnet = self.get_params(key='subnet', params=arg, default=None)
            self.subnetaddr = self.get_params(key='subnetaddr', params=arg, default=None)
            self.vnetaddr = self.get_params(key='vnetaddr', params=arg, default=None)

            self.async = self.get_params(key='async', params=arg, default=None)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)

            if self.location:
                self.group = None
            if not self.location and not self.group:
                logger('%s: must specify either location of affinity group' % inspect.stack()[0][3])
                sys.exit(1)

            self.body = self.xml_networkconfig_fragment_from_dict(dns=self.dns, ipaddr=self.ipaddr,
                                                                  group=self.group, location=self.location,
                                                                  network=self.network, vnetaddr=self.vnetaddr,
                                                                  subnet=self.subnet, subnetaddr=self.subnetaddr)
            
            self.path = '/%s/services/networking/media' % self.subscription_id
            
            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                d = dict()
                if not self.async:                  
                    d['result'] = self.perform_put(path=self.path, body=self.body, content_type='text/plain')
                    request_id = [req_id[1] for req_id in d['result']['headers'] if req_id[0] == 'x-ms-request-id'][0]
                    operation = self.sms.get_operation_status(request_id)
                    d['operation'] = operation.__dict__
                    d['operation_result'] = self.wait_for_operation_status(request_id=request_id)
                    return d                    
                else:
                    return self.perform_put(path=path, body=body, content_type='text/plain')
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])                
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def create_hosted_service(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.service = self.get_params(key='service', params=arg, default=None)
            self.label = self.get_params(key='label', params=arg, default=self.service)
            self.description = self.get_params(key='description', params=arg, default=None)
            self.location = self.get_params(key='location', params=arg, default=self.default_location)
            self.group = self.get_params(key='group', params=arg, default=None)
            self.account = self.get_params(key='account', params=arg, default=self.default_storage_account)
            self.extended_properties = self.get_params(key='extended_properties', params=arg,
                                                       default=self.get_storage_account_properties({'account': self.account,
                                                                                                    'verbose': False})['extended_properties'])
            self.async = self.get_params(key='async', params=arg, default=None)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)

            if self.group: self.location = None
            if not self.location and not self.group:
                logger('%s: must specify either location of affinity group' % inspect.stack()[0][3])
                sys.exit(1)

            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                try:
                    d = dict()
                    result = self.sms.create_hosted_service(self.service, self.label,
                                                            location=self.location, description=self.description,
                                                            affinity_group=self.group,
                                                            extended_properties=self.extended_properties)
                    d['result'] = result.__dict__
                    if not self.async:
                        operation = self.sms.get_operation_status(result.request_id)
                        d['operation'] = operation.__dict__
                        d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                        return d
                    else:
                        return 
                except (WindowsAzureConflictError) as e:
                    logger('%s: operation in progress or resource exists, try again..' % inspect.stack()[0][3])
                    return False
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
    
    def create_reserved_ip_address(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.ipaddr = self.get_params(key='ipaddr', params=arg, default=None)
            if isinstance(self.ipaddr, list): self.ipaddr = self.ipaddr[0]
            self.label = self.get_params(key='label', params=arg, default=self.ipaddr)
            self.location = self.get_params(key='location', params=arg, default=self.default_location)
            self.async = self.get_params(key='async', params=arg, default=None)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)

            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                try:
                    d = dict()
                    result = self.sms.create_reserved_ip_address(self.ipaddr, label=self.label, location=self.location)
                    d['result'] = result.__dict__
                    if not self.async:
                        operation = self.sms.get_operation_status(result.request_id)
                        d['operation'] = operation.__dict__
                        d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                        return d
                    else:
                        return 
                except (WindowsAzureConflictError) as e:
                    logger('%s: operation in progress or resource exists, try again..' % inspect.stack()[0][3])
                    return False
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
        
    def create_storage_account(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.account = self.get_params(key='account', params=arg, default=None)
            self.account_type = self.get_params(key='account_type', params=arg, default=None)
            self.label = self.get_params(key='label', params=arg, default=self.account)
            self.description = self.get_params(key='description', params=arg, default=self.label)
            self.group = self.get_params(key='group', params=arg, default=None)
            self.location = self.get_params(key='location', params=arg, default=self.default_location)
            self.extended_properties = self.get_params(key='extended_properties', params=arg, default=None)
            self.async = self.get_params(key='async', params=arg, default=None)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)

            if self.group: self.location = None
            if not self.location and not self.group:
                logger('%s: must specify either location of affinity group' % inspect.stack()[0][3])
                sys.exit(1)                

            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                try:
                    d = dict()
                    result = self.sms.create_storage_account(self.account, self.description, self.label,
                                                             affinity_group=self.group, location=self.location,
                                                             geo_replication_enabled=None,
                                                             extended_properties=self.extended_properties,
                                                             account_type=self.account_type)
                    d['result'] = result.__dict__
                    if not self.async:
                        operation = self.sms.get_operation_status(result.request_id)
                        d['operation'] = operation.__dict__
                        d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                        return d
                    else:
                        return 
                except (WindowsAzureConflictError) as e:
                    logger('%s: operation in progress or resource exists, try again..' % inspect.stack()[0][3])
                    return False
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
        
    def create_vm_image(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.blob = self.get_params(key='blob', params=arg, default=None)
            self.name = self.get_params(key='name', params=arg, default=self.blob)
            if isinstance(self.name, list): self.name = self.name[0]            
            self.label = self.get_params(key='label', params=arg, default=self.name)
            self.description = self.get_params(key='label', params=arg, default=self.label)
            self.account = self.get_params(key='account', params=arg, default=self.default_storage_account)
            self.os = self.get_params(key='os', params=arg, default=None)
            self.os_state = self.get_params(key='os_state', params=arg, default=self.default_os_state)
            self.host_caching = self.get_params(key='host_caching', params=arg, default=self.default_host_caching)
            self.language = self.get_params(key='language', params=arg, default=None)
            self.family = self.get_params(key='family', params=arg, default=None)
            self.disk_size = self.get_params(key='disk_size', params=arg, default=self.default_disk_size)
            self.size = self.get_params(key='size', params=arg, default=self.default_size)
            self.eula_uri = self.get_params(key='eula_uri', params=arg, default=None)
            self.icon_uri = self.get_params(key='icon_uri', params=arg, default=None)
            self.small_icon_uri = self.get_params(key='small_icon_uri', params=arg, default=None)
            self.show_in_gui = self.get_params(key='show_in_gui', params=arg, default=None)
            self.privacy_uri = self.get_params(key='privacy_uri', params=arg, default=None)
            self.async = self.get_params(key='async', params=arg, default=None)    
            self.readonly = self.get_params(key='readonly', params=arg, default=None)                
            verbose = self.get_params(key='verbose', params=arg, default=None)

            vm_image = VMImage()
            vm_image.name = self.name
            vm_image.label = self.label
            vm_image.description = self.description
            vm_image.eula = self.eula_uri
            vm_image.icon_uri = self.icon_uri
            vm_image.small_icon_uri = self.small_icon_uri
            vm_image.published_date = mkdate(datetime.now(), '%Y-%m-%d')
            vm_image.show_in_gui = self.show_in_gui
            vm_image.privacy_uri = self.privacy_uri

            media_link = 'https://%s.blob.core.windows.net/%s/%s' % (self.account,
                                                                     'vhds',
                                                                     self.blob[0])
            
            vm_image.os_disk_configuration = OSVirtualHardDisk()
            vm_image.os_disk_configuration.os = self.os
            vm_image.os_disk_configuration.os_state = self.os_state
            vm_image.os_disk_configuration.media_link = media_link
            vm_image.os_disk_configuration.host_caching = self.host_caching
            
            if len(self.blob) > 1:
                vm_image.data_disk_configurations = DataVirtualHardDisks()
                for i in range(1, len(self.blob)):
                    data_disk_configuration = DataVirtualHardDisk()
                    data_disk_configuration.logical_disk_size_in_gb = self.disk_size
                    media_link = 'https://%s.blob.core.windows.net/%s/%s' % (self.account,
                                                                             'images',
                                                                             self.blob[i])
                    data_disk_configuration.host_caching = self.host_caching
                    data_disk_configuration.lun = i
                    data_disk_configuration.media_link = media_link                 
                    vm_image.data_disk_configurations.data_virtual_hard_disks.append(data_disk_configuration)
            
            vm_image.language = self.language
            vm_image.image_family = self.family
            vm_image.recommended_vm_size = self.size
            self.vm_image = vm_image
            
            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                try:
                    d = dict()                    
                    result = self.sms.create_vm_image(self.vm_image)
                    d['result'] = result.__dict__
                    if not self.async:
                        operation = self.sms.get_operation_status(result.request_id)
                        d['operation'] = operation.__dict__
                        d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                        return d
                    else:
                        return 
                except (WindowsAzureConflictError) as e:
                    logger('%s: operation in progress or resource exists, try again..' % inspect.stack()[0][3])
                    return False
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def dict_from_response_obj(self, *args):
        obj = args[0]

        if '__dict__' in dir(obj):
            obj = self.dict_from_response_obj(obj.__dict__)
        elif isinstance(obj, dict):            
            for k, v in obj.iteritems():
                if '__dict__' in dir(v):
                    obj[k] = self.dict_from_response_obj(v.__dict__)
                if isinstance(v, dict):
                    v = recurse_dict(v)            
                if isinstance(v, list):
                    for el in v:
                        obj[k] = self.dict_from_response_obj(el)
        return obj 
   
    def delete_affinity_group(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.name = self.get_params(key='name', params=arg, default=None)
            if isinstance(self.name, list): self.name = self.name[0]
            self.async = self.get_params(key='async', params=arg, default=None)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)

            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                return self.sms.delete_affinity_group(self.name)
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
            
    def delete_role(self, *args):        
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.name = self.get_params(key='name', params=arg, default=None)     
            if isinstance(self.name, list): self.name = self.name[0]
            self.service = self.get_params(key='service', params=arg, default=None)     
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.async = self.get_params(key='async', params=arg, default=None)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            self.delete_disks = self.get_params(key='delete_disks', params=arg, default=None)
            self.delete_vhds = self.get_params(key='delete_vhds', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)

            d = dict()
            d['disks'] = self.get_disk_by_role_name({'service': self.service, 'deployment': self.deployment,
                                                     'name': self.name, 'verbose': False})
            
            if verbose:
                pprint.pprint(self.__dict__)
                pprint.pprint(d)

            if not self.readonly:
                result = self.sms.delete_role(self.service, self.deployment, self.name)
                d['result'] = result.__dict__
                if not self.async:
                    operation = self.sms.get_operation_status(result.request_id)
                    d['result'] = result.__dict__
                    d['operation'] = operation.__dict__
                    d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                    d['delete_disks'] = list()
                    if self.delete_disks:
                        for disk in d['disks']:
                            d['delete_disks'] = list()
                            logger(message='%s: deleting disk %s attached to %s' % (inspect.stack()[0][3],
                                                                                    disk['name'],
                                                                                    disk['attached_to']))
                            d['delete_disks'].append({'result': self.delete_disk({'disk': disk['name'],
                                                                                  'delete_vhds': self.delete_vhds,
                                                                                  'readonly': self.readonly,
                                                                                  'verbose': False}),
                                                      'disk': disk['name']})
                    return d
                else:                    
                    return d
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False    

    def delete_disk(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False
            
            self.disk = self.get_params(key='disk', params=arg, default=None)
            self.delete_vhds = self.get_params(key='delete_vhds', params=arg, default=None)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)

            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:

                @retry(WindowsAzureConflictError, tries=5, delay=15, backoff=2, cdata='method=%s()' % inspect.stack()[0][3])
                def delete_disk_retry():
                    return self.sms.delete_disk(self.disk, delete_vhd=self.delete_vhds)
                
                return delete_disk_retry()
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
    
    def delete_dns_server(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.dns = self.get_params(key='dns', params=arg, default=None)
            if isinstance(self.dns, list): self.dns = self.dns[0]
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)
            self.async = self.get_params(key='async', params=arg, default=None)
            
            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                result = self.sms.delete_dns_server(self.service, self.deployment, self.dns)        
                if result is not None:
                        d = dict()
                        operation = self.sms.get_operation_status(result.request_id)
                        d['result'] = result.__dict__
                        d['operation'] = operation.__dict__
                        if not self.async:
                            d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                            return d
                        else:
                            return d                        
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
    
    def delete_hosted_service(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.service = self.get_params(key='service', params=arg, default=None)
            self.delete_disks = self.get_params(key='delete_disks', params=arg, default=None)
            self.delete_vhds = self.get_params(key='delete_vhds', params=arg, default=None)
            self.async = self.get_params(key='async', params=arg, default=None)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)

            self.complete = False
            if self.delete_disks and self.delete_vhds: self.complete = True
            
            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                result = self.sms.delete_hosted_service(self.service, self.complete)        
                if result is not None:
                    d = dict()
                    operation = self.sms.get_operation_status(result.request_id)
                    d['result'] = result.__dict__
                    d['operation'] = operation.__dict__
                    if not self.async:
                        d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                        return d
                    else:
                        return d
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
    
    def delete_management_certificate(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.thumbprint = self.get_params(key='thumbprint', params=arg, default=None)
            self.async = self.get_params(key='async', params=arg, default=None)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)
            
            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                result = self.sms.delete_management_certificate(self.thumbprint)        
                if result is not None:
                    d = dict()
                    operation = self.sms.get_operation_status(result.request_id)
                    d['result'] = result.__dict__
                    d['operation'] = operation.__dict__
                    if not self.async:
                        d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                        return d
                    else:
                        return d
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
    
    def delete_os_image(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.name = self.get_params(key='name', params=arg, default=None)
            if isinstance(self.name, list): self.name = self.name[0]
            self.delete_vhds = self.get_params(key='delete_vhds', params=arg, default=None)
            self.async = self.get_params(key='async', params=arg, default=None)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)

            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                try:
                    result = self.sms.delete_os_image(self.name, delete_vhd=self.delete_vhds)
                    d = dict()
                    operation = self.sms.get_operation_status(result.request_id)
                    d['result'] = result.__dict__
                    d['operation'] = operation.__dict__
                    if not self.async:
                        d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                        return d
                    else:
                        return d
                except (WindowsAzureConflictError) as e:
                    logger('%s: operation in progress or resource exists, try again..' % inspect.stack()[0][3])
                    return False
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
    
    def delete_reserved_ip_address(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.ipaddr = self.get_params(key='ipaddr', params=arg, default=None)
            if isinstance(self.ipaddr, list): self.ipaddr = self.ipaddr[0]
            self.async = self.get_params(key='async', params=arg, default=None)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)

            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                try:
                    result = self.sms.delete_reserved_ip_address(self.ipaddr)
                    d = dict()
                    operation = self.sms.get_operation_status(result.request_id)
                    d['result'] = result.__dict__
                    d['operation'] = operation.__dict__
                    if not self.async:
                        d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                        return d
                    else:
                        return d
                except (WindowsAzureConflictError) as e:
                    logger('%s: operation in progress or resource exists, try again..' % inspect.stack()[0][3])
                    return False
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
    
    def delete_role_instances(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.name = self.get_params(key='name', params=arg, default=None)            
            self.async = self.get_params(key='async', params=arg, default=None)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)

            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                try:
                    result = self.sms.delete_role_instances(self.service, self.deployment, self.name)
                    d = dict()
                    operation = self.sms.get_operation_status(result.request_id)
                    d['result'] = result.__dict__
                    d['operation'] = operation.__dict__
                    if not self.async:
                        d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                        return d
                    else:
                        return d
                except (WindowsAzureConflictError) as e:
                    logger('%s: operation in progress or resource exists, try again..' % inspect.stack()[0][3])
                    return False
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
    
    def delete_service_certificate(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.service = self.get_params(key='service', params=arg, default=None)
            self.thumbprint = self.get_params(key='thumbprint', params=arg, default=None)
            self.algorithm = self.get_params(key='algorithm', params=arg, default=self.default_algorithm)
            self.async = self.get_params(key='async', params=arg, default=None)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)
            
            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                result = self.sms.delete_service_certificate(self.service, self.algorithm, self.thumbprint)        
                if result is not None:
                    d = dict()
                    operation = self.sms.get_operation_status(result.request_id)
                    d['result'] = result.__dict__
                    d['operation'] = operation.__dict__
                    if not self.async:
                        d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                        return d
                    else:
                        return d
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
    
    def delete_storage_account(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.account = self.get_params(key='account', params=arg, default=None)
            self.async = self.get_params(key='async', params=arg, default=None)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)
            
            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                result = self.sms.delete_storage_account(self.account)        
                if result is not None:
                    d = dict()
                    operation = self.sms.get_operation_status(result.request_id)
                    d['result'] = result.__dict__
                    d['operation'] = operation.__dict__
                    if not self.async:
                        d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                        return d
                    else:
                        return d
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
    
    def delete_vm_image(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.name = self.get_params(key='name', params=arg, default=None)
            if isinstance(self.name, list): self.name = self.name[0]
            self.delete_vhds = self.get_params(key='delete_vhds', params=arg, default=None)
            self.async = self.get_params(key='async', params=arg, default=None)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)

            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                try:
                    result = self.sms.delete_vm_image(self.name, delete_vhd=self.delete_vhds)
                    d = dict()
                    operation = self.sms.get_operation_status(result.request_id)
                    d['result'] = result.__dict__
                    d['operation'] = operation.__dict__
                    if not self.async:
                        d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                        return d
                    else:
                        return d
                except (WindowsAzureConflictError) as e:
                    logger('%s: operation in progress or resource exists, try again..' % inspect.stack()[0][3])
                    return False
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
    
    def delete_data_disk(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False
            
            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.name = self.get_params(key='name', params=arg, default=None)
            if isinstance(self.name, list): self.name = self.name[0]
            self.lun = self.get_params(key='lun', params=arg, default=None)
            self.delete_vhds = self.get_params(key='delete_vhds', params=arg, default=None)
            self.async = self.get_params(key='async', params=arg, default=None)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)

            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:

                @retry(WindowsAzureConflictError, tries=5, delay=15, backoff=2, cdata='method=%s()' % inspect.stack()[0][3])
                def delete_data_disk_retry():
                    result = self.sms.delete_data_disk(self.service, self.deployment, self.name,
                                                       self.lun, delete_vhd=False)
                    d = dict()
                    operation = self.sms.get_operation_status(result.request_id)
                    d['result'] = result.__dict__
                    d['operation'] = operation.__dict__
                    if not self.async:
                        d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                        return d
                    else:
                        return d
                
                return delete_data_disk_retry()
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
    
    def delete_deployment(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.name = self.get_params(key='name', params=arg, default=None)
            if isinstance(self.name, list): self.name = self.name[0]
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)
            self.async = self.get_params(key='async', params=arg, default=None)
            self.delete_vhds = self.get_params(key='delete_vhds', params=arg, default=None)
            
            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                result = self.sms.delete_deployment(self.service, self.deployment, delete_vhds=self.delete_vhds)        
                if result is not None:
                    if not self.readonly:
                        d = dict()
                        operation = self.sms.get_operation_status(result.request_id)
                        d['result'] = result.__dict__
                        d['operation'] = operation.__dict__
                        if not self.async:
                            d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                            return d
                        else:
                            return d
                    else:
                        logger('%s: limited to read-only operations' % inspect.stack()[0][3])
                else:
                    return False
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def generate_signed_blob_url(self, **kwargs):
        try:
            if not kwargs: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=kwargs)
            if not arg: return False
            
            self.account = self.get_params(key='account', params=arg, default=None)
            self.container = self.get_params(key='container', params=arg, default=None)
            self.script = self.get_params(key='script', params=arg, default=None)

            key = self.get_storage_account_keys({'account': self.account, 'verbose': False})['storage_service_keys']['primary']       
            sas = SharedAccessSignature(account_name=self.account,account_key=key)
            ap = AccessPolicy()
            ap.expiry = (datetime.now() + timedelta(days=1)).strftime('%Y-%m-%dT%H:%S:%MZ')
            ap.permission = 'r'
            sap = SharedAccessPolicy(ap)
            path = '/%s/%s' % (self.container, self.script)                
            query = sas.generate_signed_query_string(path, 'b', sap)
            url = 'https://%s.blob.core.windows.net%s?%s' % (self.account, path, query)
            return self.urlencode_sig_query_string_part(url)               
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def get_storage_account_properties(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False
            
            self.account = self.get_params(key='account', params=arg, default=self.default_storage_account)
            verbose = self.get_params(key='verbose', params=arg, default=None)
            
            if verbose: pprint.pprint(self.__dict__)

            result = self.sms.get_storage_account_properties(self.account)
            if result:
                return self.dict_from_response_obj(result)
            else:
                return None
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def get_affinity_group_properties(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False
            
            self.name = self.get_params(key='name', params=arg, default=None)
            if isinstance(self.name, list): self.name = self.name[0]
            verbose = self.get_params(key='verbose', params=arg, default=None)
            
            if verbose: pprint.pprint(self.__dict__)
            
            result = self.sms.get_affinity_group_properties(self.name)
            if result:
                return self.dict_from_response_obj(result)
            else:
                return None
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def get_deployment_by_name(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False
            
            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)
            
            if verbose: pprint.pprint(self.__dict__)
            
            result = self.sms.get_deployment_by_name(self.service, self.deployment)
            
            if result:
                return self.dict_from_response_obj(result)
            else:
                return None
        except Exception as e:
            logger(message=traceback.print_exc())
            return False 
    
    def get_deployment_by_slot(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False
            
            self.service = self.get_params(key='service', params=arg, default=None)
            self.slot = self.get_params(key='slot', params=arg, default=self.default_deployment_slot)
            verbose = self.get_params(key='verbose', params=arg, default=None)
            
            if verbose: pprint.pprint(self.__dict__)
            
            result = self.sms.get_deployment_by_slot(self.service, self.slot)
            
            if result:
                return self.dict_from_response_obj(result)
            else:
                return None
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def get_data_disk(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False
            
            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.name = self.get_params(key='name', params=arg, default=None)            
            if isinstance(self.name, list): self.name = self.name[0]
            self.lun = self.get_params(key='lun', params=arg, default=1)
       
            result = self.sms.get_data_disk(self.service, self.deployment, self.name, self.lun)
            verbose = self.get_params(key='verbose', params=arg, default=None)
            
            if verbose: pprint.pprint(self.__dict__)            

            if result:
                return self.dict_from_response_obj(result)
            else:
                return None
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
    
    def get_disk(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False
            
            self.disk = self.get_params(key='disk', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)
            
            if verbose: pprint.pprint(self.__dict__)
            
            result = self.sms.get_disk(self.disk)
            
            if result:
                return self.dict_from_response_obj(result)
            else:
                return None
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def get_hosted_service_properties(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False
            
            self.service = self.get_params(key='service', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)
            
            if verbose: pprint.pprint(self.__dict__)
            
            result = self.sms.get_hosted_service_properties(self.service)
            
            if result:
                return self.dict_from_response_obj(result)
            else:
                return None
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def get_management_certificate(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False
            
            self.thumbprint = self.get_params(key='thumbprint', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)
            
            if verbose: pprint.pprint(self.__dict__)
            
            result = self.sms.get_management_certificate(self.thumbprint)
            
            if result:
                return self.dict_from_response_obj(result)
            else:
                return None
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
        
    def get_operation_status(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False
            
            self.request_id = self.get_params(key='request_id', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)
            
            if verbose: pprint.pprint(self.__dict__)
            
            result = self.sms.get_operation_status(self.request_id)
            
            if result:
                return self.dict_from_response_obj(result)
            else:
                return None
        except Exception as e:
            logger(message=traceback.print_exc())
            return False       

    def get_os_image(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False
            
            self.name = self.get_params(key='name', params=arg, default=None)
            if isinstance(self.name, list): self.name = self.name[0]
            verbose = self.get_params(key='verbose', params=arg, default=None)
            
            if verbose: pprint.pprint(self.__dict__)
            
            result = self.sms.get_os_image(self.name)
            
            if result:
                return self.dict_from_response_obj(result)
            else:
                return None
        except Exception as e:
            logger(message=traceback.print_exc())
            return False  

    def get_reserved_ip_address(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False
            
            self.ipaddr = self.get_params(key='ipaddr', params=arg, default=None)
            if isinstance(self.ipaddr, list): self.ipaddr = self.ipaddr[0]
            verbose = self.get_params(key='verbose', params=arg, default=None)
            
            if verbose: pprint.pprint(self.__dict__)
            
            result = self.sms.get_reserved_ip_address(self.ipaddr)
            
            if result:
                return self.dict_from_response_obj(result)
            else:
                return None
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def get_service_certificate(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False
            
            self.service = self.get_params(key='service', params=arg, default=None)
            self.algorithm = self.get_params(key='algorithm', params=arg, default=self.default_algorithm)
            self.thumbprint = self.get_params(key='thumbprint', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)
            
            if verbose: pprint.pprint(self.__dict__)
            
            result = self.sms.get_service_certificate(self.service, self.algorithm, self.thumbprint)
            
            if result:
                return self.dict_from_response_obj(result)
            else:
                return None
        except Exception as e:
            logger(message=traceback.print_exc())
            return False    
        
    def get_storage_account_keys(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False
            
            self.account = self.get_params(key='account', params=arg, default=self.default_storage_account)
            verbose = self.get_params(key='verbose', params=arg, default=None)
            
            if verbose: pprint.pprint(self.__dict__)
            
            result = self.sms.get_storage_account_keys(self.account)
            
            if result:
                return self.dict_from_response_obj(result)
            else:
                return None
        except Exception as e:
            logger(message=traceback.print_exc())
            return False  

    def get_subscription(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False
      
            verbose = self.get_params(key='verbose', params=arg, default=None)
            
            if verbose: pprint.pprint(self.__dict__)
            
            result = self.sms.get_subscription()
            
            if result:
                return self.dict_from_response_obj(result)
            else:
                return None
        except Exception as e:
            logger(message=traceback.print_exc())
            return False  

    def get_disk_by_role_name(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False
            
            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.name = self.get_params(key='name', params=arg, default=None)
            if isinstance(self.name, list): self.name = self.name[0]
            verbose = self.get_params(key='verbose', params=arg, default=None)
            
            if verbose: pprint.pprint(self.__dict__)
            
            disks = self.list_collection({'action': 'list_disks', 'verbose': False})
            
            result = []
            result = [k for k in disks if k['attached_to'] is not None and
                      k['attached_to']['role_name'] == self.name and
                      k['attached_to']['deployment_name'] == self.deployment and
                      k['attached_to']['hosted_service_name'] == self.service]
            return result
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def host(self):
        return self.sms.host

    def list_resource_extension_versions(self, *args):
        try:            
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.publisher = self.get_params(key='publisher', params=arg, default=self.default_publisher)           
            self.extension = self.get_params(key='extension', params=arg, default=self.default_extension)           
            verbose = self.get_params(key='verbose', params=arg, default=None)
            
            if verbose: pprint.pprint(self.__dict__)
               
            versions = self.sms.list_resource_extension_versions(self.publisher, self.extension)
            l = []
            for version in versions:
                l.append(self.dict_from_response_obj(version))
            return l
        except Exception as e:
            logger(message=traceback.print_exc())
            return False 
       
    def list_service_certificates(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.service = self.get_params(key='service', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)
            
            if verbose: pprint.pprint(self.__dict__)
            
            certificates = self.sms.list_service_certificates(self.service)
            l = []
            for certificate in certificates:
                l.append(self.dict_from_response_obj(certificate))
            return l
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def list_subscription_operations(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.start_date = self.get_params(key='start_date', params=arg, default=self.default_start_date)           
            self.end_date = self.get_params(key='end_date', params=arg, default=self.default_end_date)
            verbose = self.get_params(key='verbose', params=arg, default=None)
            
            if verbose: pprint.pprint(self.__dict__)
            
            operations = self.sms.list_subscription_operations(self.start_date, self.end_date)
            l = []        
            for operation in operations.subscription_operations:
                l.append(self.dict_from_response_obj(operation))
            return l    
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
    
    def list_collection(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.action = self.get_params(key='action', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)
            
            if verbose: pprint.pprint(self.__dict__)
            
            method = getattr(self.sms, self.action)
            results = method()
            l = []
            for item in results:
                l.append(self.dict_from_response_obj(item))
            return l
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def list_dns_servers(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.service = self.get_params(key='service', params=arg, default=self.default_start_date)           
            self.deployment = self.get_params(key='deployment', params=arg, default=self.default_end_date)
            verbose = self.get_params(key='verbose', params=arg, default=None)

            path = '/%s/services/hostedservices/%s/deployments/%s' % (self.subscription_id,
                                                                                 self.service,
                                                                                 self.deployment)
            if verbose: pprint.pprint(self.__dict__)
            
            response = self.perform_get(path=path, verbose=False)
            if response:                
                if 'Dns' in xmltodict.parse(response['body'])['Deployment']:
                    return xmltodict.parse(response['body'])['Deployment']['Dns']                
        except Exception as e:
            logger(message=traceback.print_exc())
            return False        

    def perform_get(self, **kwargs):
        try:
            if not kwargs: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=kwargs)
            if not arg: return False
            
            self.path = self.get_params(key='path', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)
            
            if verbose: pprint.pprint(self.__dict__)
            
            return self.sms.perform_get(self.path, x_ms_version=self.sms.x_ms_version).__dict__
        except Exception as e:
            logger(message=traceback.print_exc())
            return False 

    def perform_delete(self, **kwargs):
        try:
            if not kwargs: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=kwargs)
            if not arg: return False
            
            self.path = self.get_params(key='path', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)
            
            if verbose: pprint.pprint(self.__dict__)
            
            @retry(WindowsAzureConflictError, tries=3, delay=10, backoff=2, cdata='method=%s()' % inspect.stack()[0][3])
            def perform_delete_retry():
                return self.sms.perform_delete(self.path, x_ms_version=self.sms.x_ms_version).__dict__
            
            return perform_delete_retry()
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
    
    def perform_post(self, **kwargs):
        try:
            if not kwargs: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=kwargs)
            if not arg: return False
            
            self.path = self.get_params(key='path', params=arg, default=None)
            self.body = self.get_params(key='body', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)
            
            if verbose: pprint.pprint(self.__dict__)
            
            @retry(WindowsAzureConflictError, tries=3, delay=10, backoff=2, cdata='method=%s()' % inspect.stack()[0][3])
            def perform_post_retry():
                return self.sms.perform_post(self.path, self.body, x_ms_version=self.sms.x_ms_version).__dict__
            
            return perform_post_retry()
        except Exception as e:
            logger(message=traceback.print_exc())
            return False 

    def perform_put(self, **kwargs):
        try:
            if not kwargs: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=kwargs)
            if not arg: return False
            
            self.path = self.get_params(key='path', params=arg, default=None)
            self.body = self.get_params(key='body', params=arg, default=None)
            self.content_type = self.get_params(key='content_type', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)
            
            if verbose: pprint.pprint(self.__dict__)

            @retry(WindowsAzureConflictError, tries=3, delay=10, backoff=2, cdata='method=%s()' % inspect.stack()[0][3])
            def perform_put_retry():

                def _my_perform_put(self, path, body, x_ms_version=None, content_type=None):
                    '''
                    Performs a PUT request and returns the response (monkey patched to accept content_type argument).

                    path:
                        Path to the resource.
                        Ex: '/<subscription-id>/services/hostedservices/<service-name>'
                    body:
                        Body for the PUT request.
                    x_ms_version:
                        If specified, this is used for the x-ms-version header.
                        Otherwise, self.x_ms_version is used.
                    '''

                    from azure import (
                        WindowsAzureError,
                        DEFAULT_HTTP_TIMEOUT,
                        MANAGEMENT_HOST,
                        WindowsAzureAsyncOperationError,
                        _ERROR_ASYNC_OP_FAILURE,
                        _ERROR_ASYNC_OP_TIMEOUT,
                        _get_request_body,
                        _str,
                        _validate_not_none,
                        _update_request_uri_query,
                        )
                    from azure.http import (
                        HTTPError,
                        HTTPRequest,
                        )
                    from azure.http.httpclient import _HTTPClient
                    from azure.servicemanagement import (
                        AZURE_MANAGEMENT_CERTFILE,
                        AZURE_MANAGEMENT_SUBSCRIPTIONID,
                        Operation,
                        _MinidomXmlToObject,
                        _management_error_handler,
                        parse_response_for_async_op,
                        X_MS_VERSION,
                        )

                    request = HTTPRequest()
                    request.method = 'PUT'
                    request.host = self.host
                    request.path = path
                    request.body = _get_request_body(body)        
                    request.path, request.query = _update_request_uri_query(request)
                    if content_type: request.headers.append(('Content-Type', content_type))
                    request.headers = self._update_management_header(request, x_ms_version)
                    response = self._perform_request(request)

                    return response

                from azure.servicemanagement.servicemanagementclient import _ServiceManagementClient as ServiceManagementClient

                mpsmc = ServiceManagementClient(subscription_id=self.subscription_id,
                                                cert_file=self.management_certificate,
                                                request_session=self.set_proxy())
                
                ServiceManagementClient.perform_put = _my_perform_put                

                return mpsmc.perform_put(self.path, self.body,
                                         x_ms_version=self.sms.x_ms_version,
                                         content_type=self.content_type).__dict__
            
            return perform_put_retry()
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def rebuild_role_instance(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.name = self.get_params(key='name', params=arg, default=None)
            if isinstance(self.name, list): self.name = self.name[0]
            self.async = self.get_params(key='async', params=arg, default=None)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)

            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                try:
                    result = self.sms.rebuild_role_instance(self.service, self.deployment, self.name)
                    d = dict()
                    operation = self.sms.get_operation_status(result.request_id)
                    d['result'] = result.__dict__
                    d['operation'] = operation.__dict__
                    if not self.async:
                        d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                        return d
                    else:
                        return d
                except (WindowsAzureConflictError) as e:
                    logger('%s: operation in progress or resource exists, try again..' % inspect.stack()[0][3])
                    return False
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
        
    def regenerate_storage_account_keys(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.account = self.get_params(key='account', params=arg, default=None)
            self.key_type = self.get_params(key='key_type', params=arg, default=self.default_key_type)
            self.async = self.get_params(key='async', params=arg, default=None)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)

            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                storage = self.sms.regenerate_storage_account_keys(self.account, self.key_type)
                return self.dict_from_response_obj(storage)
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
    
    def reimage_role_instance(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.name = self.get_params(key='name', params=arg, default=None)
            if isinstance(self.name, list): self.name = self.name[0]
            self.async = self.get_params(key='async', params=arg, default=None)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)

            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                try:
                    result = self.sms.reimage_role_instance(self.service, self.deployment, self.name)
                    d = dict()
                    operation = self.sms.get_operation_status(result.request_id)
                    d['result'] = result.__dict__
                    d['operation'] = operation.__dict__
                    if not self.async:
                        d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                        return d
                    else:
                        return d
                except (WindowsAzureConflictError) as e:
                    logger('%s: operation in progress or resource exists, try again..' % inspect.stack()[0][3])
                    return False
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
    
    def rollback_update_or_upgrade(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.mode = self.get_params(key='mode', params=arg, default=self.default_mode)
            self.force = self.get_params(key='force', params=arg, default=None)
            self.async = self.get_params(key='async', params=arg, default=None)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)

            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                try:
                    result = self.sms.rollback_update_or_upgrade(self.service, self.deployment, self.mode, self.force)
                    d = dict()
                    operation = self.sms.get_operation_status(result.request_id)
                    d['result'] = result.__dict__
                    d['operation'] = operation.__dict__
                    if not self.async:
                        d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                        return d
                    else:
                        return d
                except (WindowsAzureConflictError) as e:
                    logger('%s: operation in progress or resource exists, try again..' % inspect.stack()[0][3])
                    return False
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
    
    def reboot_role_instance(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.name = self.get_params(key='name', params=arg, default=None)
            if isinstance(self.name, list): self.name = self.name[0]
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            self.async = self.get_params(key='async', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)
            
            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                result = self.sms.reboot_role_instance(self.service, self.deployment, self.name)       
                if result is not None:
                    if not self.readonly:
                        d = dict()
                        operation = self.sms.get_operation_status(result.request_id)
                        d['result'] = result.__dict__
                        d['operation'] = operation.__dict__
                        if not self.async:
                            d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                            return d
                        else:
                            return d
                    else:
                        logger('%s: limited to read-only operations' % inspect.stack()[0][3])
                else:
                    return False
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
    
    def start_role(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.name = self.get_params(key='name', params=arg, default=None)
            if isinstance(self.name, list): self.name = self.name[0]
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            self.async = self.get_params(key='async', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)
            
            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                result = self.sms.start_role(self.service, self.deployment, self.name)  
                if result is not None:
                    if not self.readonly:
                        d = dict()
                        operation = self.sms.get_operation_status(result.request_id)
                        d['result'] = result.__dict__
                        d['operation'] = operation.__dict__
                        if not self.async:
                            d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                            return d
                        else:
                            return d
                    else:
                        logger('%s: limited to read-only operations' % inspect.stack()[0][3])
                else:
                    return False
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
    
    def start_roles(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.name = self.get_params(key='name', params=arg, default=None)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            self.async = self.get_params(key='async', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)
            
            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                result = self.sms.start_roles(self.service, self.deployment, self.name)
                if result is not None:
                    d = dict()
                    operation = self.sms.get_operation_status(result.request_id)
                    d['result'] = result.__dict__
                    d['operation'] = operation.__dict__
                    if not self.async:
                        d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                        return d
                    else:
                        return d
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
        
    def restart_role(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.name = self.get_params(key='name', params=arg, default=None)
            if isinstance(self.name, list): self.name = self.name[0]
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            self.async = self.get_params(key='async', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)
            
            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                result = self.sms.restart_role(self.service, self.deployment, self.name) 
                if result is not None:
                    if not self.readonly:
                        d = dict()
                        operation = self.sms.get_operation_status(result.request_id)
                        d['result'] = result.__dict__
                        d['operation'] = operation.__dict__
                        if not self.async:
                            d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                            return d
                        else:
                            return d
                    else:
                        logger('%s: limited to read-only operations' % inspect.stack()[0][3])
                else:
                    return False
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def request_session(self):
        return self.sms.request_session
    
    def requestid(self):        
        return self.sms.requestid

    def set_proxy(self):
        if self.proxy == 'True':
            s = Session()
            s.cert = self.default_management_certificate
            if self.ssl_verify == 'True':
                s.verify = True
            else:
                s.verify = False
            s.proxies = {'http' : 'http://%s:%s' % (self.proxy_host, self.proxy_port),
                         'https': 'https://%s:%s' % (self.proxy_host, self.proxy_port)}
            return s
        else:
            return None

    def sub_id(self):
        return self.sms.subscription_id
    
    def shutdown_role(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.name = self.get_params(key='name', params=arg, default=None)
            if isinstance(self.name, list): self.name = self.name[0]
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            self.async = self.get_params(key='async', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)
            
            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                result = self.sms.shutdown_role(self.service, self.deployment, self.name) 
                if result is not None:
                    if not self.readonly:
                        d = dict()
                        operation = self.sms.get_operation_status(result.request_id)
                        d['result'] = result.__dict__
                        d['operation'] = operation.__dict__
                        if not self.async:
                            d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                            return d
                        else:
                            return d
                    else:
                        logger('%s: limited to read-only operations' % inspect.stack()[0][3])
                else:
                    return False
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
                             
    def shutdown_roles(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.name = self.get_params(key='name', params=arg, default=None)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            self.async = self.get_params(key='async', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)

            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                result = self.sms.shutdown_roles(self.service, self.deployment, self.name)
                if result is not None:
                    d = dict()
                    operation = self.sms.get_operation_status(result.request_id)
                    d['result'] = result.__dict__
                    d['operation'] = operation.__dict__
                    if not self.async:
                        d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                        return d
                    else:
                        return d
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def swap_deployment(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.production_deployment = self.get_params(key='production_deployment', params=arg, default=None)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            self.async = self.get_params(key='async', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)
            
            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                result = self.sms.swap_deployment(self.service, self.production_deployment, self.deployment) 
                if result is not None:
                    if not self.readonly:
                        d = dict()
                        operation = self.sms.get_operation_status(result.request_id)
                        d['result'] = result.__dict__
                        d['operation'] = operation.__dict__
                        if not self.async:
                            d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                            return d
                        else:
                            return d
                    else:
                        logger('%s: limited to read-only operations' % inspect.stack()[0][3])
                else:
                    return False
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def xml_endpoint_fragment_from_dict(self, **kwargs):
        try:
            if not kwargs: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=kwargs)
            if not arg: return False

            self.epacls = self.get_params(key='epacls', params=arg, default=None)
            
            if self.epacls:
                root = Element('InputEndpoints')
                for epel in self.epacls:
                    ep = SubElement(root, 'InputEndpoint')
                    local_port = SubElement(ep, 'LocalPort')
                    local_port.text = epel['LocalPort']
                    name = SubElement(ep, 'Name')
                    name.text = epel['Name']
                    port = SubElement(ep, 'Port')
                    port.text = epel['Port']
                    protocol = SubElement(ep, 'Protocol')
                    protocol.text = epel['Protocol']
                    if 'acls' in epel:
                        acl = SubElement(ep, 'EndpointAcl')
                        rules = SubElement(acl, 'Rules')
                        i = 100
                        for acel in epel['acls']:
                            rule = SubElement(rules, 'Rule')
                            order = SubElement(rule, 'Order')
                            order.text = str(i)
                            action = SubElement(rule, 'Action')
                            action.text = 'permit'
                            subnet = SubElement(rule, 'RemoteSubnet')
                            subnet.text = acel[1]
                            description = SubElement(rule, 'Description')
                            description.text = acel[0]
                            i = i + 1
                return tostring(root)
            else:
                return None
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
        
    def build_default_epacl_dict_for_os(self, **kwargs):
        try:
            os = kwargs['os']
            eps = self.default_endpoints
            acls = self.default_remote_subnets
            for ep in eps[os]:
                ep['acls'] = acls            
            return eps[os]
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
    
    def set_epacls(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False
            
            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.name = self.get_params(key='name', params=arg, default=None)
            if isinstance(self.name, list): self.name = self.name[0]
            self.subnet = self.get_params(key='subnet', params=arg, default=None)
            if isinstance(self.subnet, list): self.subnet = self.subnet[0]
            self.epacls = self.get_params(key='epacls', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)

            if not self.epacls:
                self.os = self.get_params(key='os', params=arg, default=self.get_role({'service': self.service,
                                                                                       'deployment': self.deployment,
                                                                                       'name': self.name,
                                                                                       'verbose': False})['os_virtual_hard_disk']['os'])
                if self.os:
                    self.epacls = self.get_params(key='epacls', params=arg,
                                                  default=self.build_default_epacl_dict_for_os(os=self.os))
                    self.eps = self.build_epacls_dict_from_xml(service=self.service,
                                                               deployment=self.deployment,
                                                               name=self.name)
                    count = 0
                    for epacl in self.epacls:
                        epacl['Port'] = self.eps[count]['Port']
                        count = count + 1   
                else:
                    return False
            if not self.epacls: return False

            body = \
            '''
            <PersistentVMRole xmlns="http://schemas.microsoft.com/windowsazure">
                    <RoleName>%s</RoleName>
                    <RoleType>PersistentVMRole</RoleType>
                    <ConfigurationSets>
                            <ConfigurationSet>
                                    <ConfigurationSetType>NetworkConfiguration</ConfigurationSetType>
                                    %s
                                    <SubnetNames>
                                            <SubnetName>%s</SubnetName>
                                    </SubnetNames>
                            </ConfigurationSet>
                    </ConfigurationSets>
                    <ResourceExtensionReferences />
                    <DataVirtualHardDisks />
                    <OSVirtualHardDisk />
                    <RoleSize>Small</RoleSize>
                    <ProvisionGuestAgent>true</ProvisionGuestAgent>
            </PersistentVMRole>
            ''' % (self.name,
                   self.xml_endpoint_fragment_from_dict(epacls=self.epacls),
                   self.subnet)
            
            path = '/%s/services/hostedservices/%s/deployments/%s/roles/%s' % (self.subscription_id,
                                                                               self.service,
                                                                               self.deployment,
                                                                               self.name)            
            if verbose: pprint.pprint(self.__dict__)

            self.async = self.get_params(key='async', params=arg, default=None)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            
            if not self.readonly:
                d = dict()
                if not self.async:                  
                    d['result'] = self.perform_put(path=path, body=body)
                    request_id = [req_id[1] for req_id in d['result']['headers'] if req_id[0] == 'x-ms-request-id'][0]
                    operation = self.sms.get_operation_status(request_id)
                    d['operation'] = operation.__dict__
                    d['operation_result'] = self.wait_for_operation_status(request_id=request_id)
                    return d                    
                else:
                    return self.perform_put(path=path, body=body)
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])                
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def get_epacls(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.name = self.get_params(key='name', params=arg, default=None)
            if isinstance(self.name, list): self.name = self.name[0]
            self.subscription_id = self.get_params(key='subscription_id', params=arg, default=self.default_subscription_id)

            path = '/%s/services/hostedservices/%s/deployments/%s/roles/%s' % (self.subscription_id,
                                                                               self.service,
                                                                               self.deployment,
                                                                               self.name)
            d = dict()
            d['result'] = self.perform_get(path=path)
            request_id = [req_id[1] for req_id in d['result']['headers'] if req_id[0] == 'x-ms-request-id'][0]
            operation = self.sms.get_operation_status(request_id)
            d['operation'] = operation.__dict__
            d['operation_result'] = self.wait_for_operation_status(request_id=request_id)
            return d
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def get_role(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False
            
            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.name = self.get_params(key='name', params=arg, default=None)
            if isinstance(self.name, list): self.name = self.name[0]
            verbose = self.get_params(key='verbose', params=arg, default=None)

            if verbose: pprint.pprint(self.__dict__)
           
            role = self.sms.get_role(self.service, self.deployment, self.name)
            if role:
                return self.dict_from_response_obj(role)
            else:
                return None
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def get_objs_for_role(self, **kwargs):
        try:
            if not kwargs: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=kwargs)
            if not arg: return False
            
            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.name = self.get_params(key='name', params=arg, default=None)
            if isinstance(self.name, list): self.name = self.name[0]
            self.key = self.get_params(key='key', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)

            if verbose: pprint.pprint(self.__dict__)

            role = self.sms.get_role(self.service, self.deployment, self.name)
            d = dict()
            if role:                
                for k, v in role.__dict__.iteritems():
                    if isinstance(v, dict):
                        v = recurse_dict(v)
                    if '__dict__' in dir(v):
                        d[k] = v                    
                return d
            else:
                return None
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
        
    def get_params(self, **kwargs):
        try:
            key = kwargs['key']
            keys = kwargs['params'].keys()
            params = kwargs['params']
            default = kwargs['default']
            if key in keys and params[key] is not None:
                return params[key]
            else:
                return default
        except KeyError:
            return None

    def timeout(self):
        return self.sms.timeout
    
    def upgrade_deployment(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.name = self.get_params(key='name', params=arg, default=None)
            if isinstance(self.name, list): self.name = self.name[0]
            self.label = self.get_params(key='name', params=arg, default=self.name)
            self.package_url = self.get_params(key='package_url', params=arg, default=None)
            self.package_config = self.get_params(key='package_config', params=arg, default=None)
            self.mode = self.get_params(key='mode', params=arg, default=self.default_mode)
            self.force = self.get_params(key='force', params=arg, default=None)
            self.account = self.get_params(key='account', params=arg, default=self.default_storage_account)            
            self.extended_properties = self.get_params(key='extended_properties', params=arg,
                                                       default=self.get_storage_account_properties({'account': self.account,
                                                                                                    'verbose': False})['extended_properties'])
            self.start_deployment = self.get_params(key='start_deployment', params=arg, default=self.default_start_deployment)
            self.ignore_warinings = self.get_params(key='ignore_warinings', params=arg, default=self.default_ignore_warinings)
            self.async = self.get_params(key='async', params=arg, default=None)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)
            
            try:
                self.package_config = None                                                    
                with open(self.package_config, 'rb') as cf:
                    self.configuration = b64encode(cf.read())
            except IOError:
                logger('%s: unable to read %s' % (inspect.stack()[0][3], self.package_config))
                pass

            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                try:
                    d = dict()
                    result = self.sms.upgrade_deployment(self.service, self.deployment, self.mode,
                                                         self.package_url, self.configuration,
                                                         self.label, self.force, 
                                                         role_to_upgrade=self.name,
                                                         extended_properties=self.extended_properties)
                    d['result'] = result.__dict__
                    if not self.async:
                        operation = self.sms.get_operation_status(result.request_id)
                        d['operation'] = operation.__dict__
                        d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                        return d
                    else:
                        return 
                except (WindowsAzureConflictError) as e:
                    logger('%s: operation in progress or resource exists, try again..' % inspect.stack()[0][3])
                    return False
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
    
    def change_deployment_configuration(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.package_config = self.get_params(key='package_config', params=arg, default=None)
            self.account = self.get_params(key='account', params=arg, default=self.default_storage_account)            
            self.mode = self.get_params(key='mode', params=arg, default=self.default_mode)            
            self.extended_properties = self.get_params(key='description', params=arg,
                                                       default=self.get_storage_account_properties({'account': self.account,
                                                                                                    'verbose': False})['extended_properties'])
            self.ignore_warinings = self.get_params(key='ignore_warinings', params=arg, default=self.default_ignore_warinings)
            self.async = self.get_params(key='async', params=arg, default=None)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)
            
            try:
                self.package_config = None                                                    
                with open(self.package_config, 'rb') as cf:
                    self.configuration = b64encode(cf.read())
            except IOError:
                logger('%s: unable to read %s' % (inspect.stack()[0][3], self.package_config))
                pass

            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                try:
                    d = dict()
                    result = self.sms.change_deployment_configuration(self.service, self.deployment, self.configuration,
                                                                      treat_warnings_as_error=self.ignore_warinings,
                                                                      mode=self.mode,
                                                                      extended_properties=self.extended_properties)
                    d['result'] = result.__dict__
                    if not self.async:
                        operation = self.sms.get_operation_status(result.request_id)
                        d['operation'] = operation.__dict__
                        d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                        return d
                    else:
                        return 
                except (WindowsAzureConflictError) as e:
                    logger('%s: operation in progress or resource exists, try again..' % inspect.stack()[0][3])
                    return False
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def update_affinity_group(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.name = self.get_params(key='name', params=arg, default=None)
            if isinstance(self.name, list): self.name = self.name[0]
            self.label = self.get_params(key='label', params=arg, default=self.name)
            self.description = self.get_params(key='description', params=arg, default=None)       
            self.async = self.get_params(key='async', params=arg, default=None)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)

            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                return self.sms.update_affinity_group(self.name, self.label, self.description)
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
    
    def update_data_disk(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.name = self.get_params(key='name', params=arg, default=None)
            if isinstance(self.name, list): self.name = self.name[0]
            self.disk = self.get_params(key='disk', params=arg, default=None)
            self.label = self.get_params(key='label', params=arg, default=self.disk)
            self.lun = self.get_params(key='lun', params=arg, default=None)
            self.media_link = self.get_params(key='media_link', params=arg, default=None)
            self.host_caching = self.get_params(key='host_caching', params=arg, default=self.default_host_caching)
            self.disk_size = self.get_params(key='disk_size', params=arg, default=self.default_disk_size)            
            self.async = self.get_params(key='async', params=arg, default=None)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)

            self.current_lun = len(self.get_disk_by_role_name({'service': self.service,
                                                               'deployment': self.deployment,
                                                               'name': self.name,
                                                               'verbose': False})) - 1
            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                try:
                    result = self.sms.update_data_disk(self.service, self.deployment, self.name, self.current_lun,
                                                       host_caching=self.host_caching,
                                                       media_link=self.media_link,
                                                       updated_lun=self.lun,
                                                       disk_label=self.label,
                                                       disk_name=self.disk,
                                                       logical_disk_size_in_gb=self.disk_size)
                    d = dict()
                    operation = self.sms.get_operation_status(result.request_id)
                    d['result'] = result.__dict__
                    d['operation'] = operation.__dict__
                    if not self.async:
                        d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                        return d
                    else:
                        return d
                except (WindowsAzureConflictError) as e:
                    logger('%s: operation in progress or resource exists, try again..' % inspect.stack()[0][3])
                    return False
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def update_deployment_status(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=self.name)
            self.deployment_status = self.get_params(key='deployment_status', params=arg, default=None)       
            self.async = self.get_params(key='async', params=arg, default=None)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)

            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                return self.sms.update_deployment_status(self.service, self.deployment, self.deployment_status)
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def update_disk(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.disk = self.get_params(key='disk', params=arg, default=None)
            self.label = self.get_params(key='label', params=arg, default=self.disk)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)

            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                try:
                    return self.sms.update_disk(self.disk, has_operating_system=None, label=self.label,
                                                media_link=None, name=None, os=None)
                except (WindowsAzureConflictError) as e:
                    logger('%s: operation in progress or resource exists, try again..' % inspect.stack()[0][3])
                    return False
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def update_dns_server(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.dns = self.get_params(key='dns', params=arg, default=None)
            if isinstance(self.dns, list): self.dns = self.dns[0]
            self.ipaddr = self.get_params(key='ipaddr', params=arg, default=None)
            if isinstance(self.ipaddr, list): self.ipaddr = self.ipaddr[0]
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)
            self.async = self.get_params(key='async', params=arg, default=None)

            if verbose: pprint.pprint(self.__dict__)
            
            result = self.sms.update_dns_server(self.service, self.deployment, self.dns, self.ipaddr)        
            if result is not None:
                if not self.readonly:
                    d = dict()
                    operation = self.sms.get_operation_status(result.request_id)
                    d['result'] = result.__dict__
                    d['operation'] = operation.__dict__
                    if not self.async:
                        d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                        return d
                    else:
                        return d
                else:
                    logger('%s: limited to read-only operations' % inspect.stack()[0][3])
            else:
                return False
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def update_hosted_service(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.service = self.get_params(key='service', params=arg, default=None)
            self.label = self.get_params(key='label', params=arg, default=None)
            self.description = self.get_params(key='description', params=arg, default=None)
            self.account = self.get_params(key='account', params=arg, default=self.default_storage_account)
            self.extended_properties = self.get_params(key='description', params=arg,
                                                       default=self.get_storage_account_properties({'account': self.account,
                                                                                                    'verbose': False})['extended_properties'])
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)
            self.async = self.get_params(key='async', params=arg, default=None)

            if verbose: pprint.pprint(self.__dict__)
            
            result = self.sms.update_hosted_service(self.service, label=self.label,
                                                    description=self.description,
                                                    extended_properties=self.extended_properties)        
            if result is not None:
                if not self.readonly:
                    d = dict()
                    operation = self.sms.get_operation_status(result.request_id)
                    d['result'] = result.__dict__
                    d['operation'] = operation.__dict__
                    if not self.async:
                        d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                        return d
                    else:
                        return d
                else:
                    logger('%s: limited to read-only operations' % inspect.stack()[0][3])
            else:
                return False
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def update_os_image(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.name = self.get_params(key='name', params=arg, default=None)
            if isinstance(self.name, list): self.name = self.name[0]
            self.label = self.get_params(key='label', params=arg, default=self.name)
            self.blob = self.get_params(key='blob', params=arg, default=None)
            if isinstance(self.blob, list): self.blob = self.blob[0]
            self.account = self.get_params(key='account', params=arg, default=self.default_storage_account)
            self.container = self.get_params(key='container', params=arg, default='images')       
            self.os = self.get_params(key='os', params=arg, default=None)

            self.async = self.get_params(key='async', params=arg, default=None)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)

            self.media_link = 'https://%s.blob.core.windows.net/%s/%s' % (self.account,
                                                                          self.container,
                                                                          self.blob)
            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                try:
                    result = self.sms.update_os_image(self.name, self.label, self.media_link,
                                                      self.blob, self.os)
                    d = dict()
                    operation = self.sms.get_operation_status(result.request_id)
                    d['result'] = result.__dict__
                    d['operation'] = operation.__dict__
                    if not self.async:
                        d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                        return d
                    else:
                        return d
                except (WindowsAzureConflictError) as e:
                    logger('%s: operation in progress or resource exists, try again..' % inspect.stack()[0][3])
                    return False
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
        
    def update_role(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.name = self.get_params(key='name', params=arg, default=None)
            if isinstance(self.name, list): self.name = self.name[0]
            verbose = self.get_params(key='verbose', params=arg, default=None)

            role = self.get_role({'service': self.service, 'deployment': self.deployment, 'name': self.name, 'verbose': False})
            
            if role:
                self.os = self.get_params(key='os', params=arg, default=role['os_virtual_hard_disk']['os'])
                self.size = self.get_params(key='size', params=arg, default=None)
                self.availset = self.get_params(key='availset', params=arg, default=None)
                self.subnet = self.get_params(key='subnet', params=arg, default=role['configuration_sets']['configuration_sets']['subnet_names'])
                if isinstance(self.subnet, list): self.subnet = self.subnet[0]
                self.rextrs = self.get_params(key='rextrs', params=arg, default=None)
                self.eps = self.get_params(key='eps', params=arg, default=role['configuration_sets']['configuration_sets']['input_endpoints']['input_endpoints'])
                if not isinstance(self.eps, list): self.eps = [self.eps]
                self.os_disk = self.get_params(key='os_disk', params=arg, default=None)
                self.data_disks = self.get_params(key='data_disk', params=arg, default=None)
                self.async = self.get_params(key='async', params=arg, default=None) 
                self.readonly = self.get_params(key='readonly', params=arg, default=None)                
            else:
                logger('%s: unable to retrieve properties for role %s' % (inspect.stack()[0][3], self.name))
                return False
          
            net_config = ConfigurationSet()
            net_config.configuration_set_type = 'NetworkConfiguration'

            if self.subnet:
                subnet = Subnet()
                subnet.name = self.subnet
                subnets = Subnets()
                subnets.subnets.append(subnet.name)
                net_config.subnet_names = subnets
                net_config.end = subnets

            if self.eps:
                endpoints = []            
                for ep in self.eps:
                    endpoints.append(ConfigurationSetInputEndpoint(name=ep['name'],
                                                                   protocol=ep['protocol'],
                                                                   port=ep['port'],
                                                                   local_port=ep['local_port'],
                                                                   load_balanced_endpoint_set_name=ep['load_balanced_endpoint_set_name'],
                                                                   enable_direct_server_return=ep['enable_direct_server_return'],
                                                                   idle_timeout_in_minutes=ep['idle_timeout_in_minutes']))                    
                for endpoint in endpoints:
                    net_config.input_endpoints.input_endpoints.append(endpoint)
                
            self.net_config = net_config

            self.epacls = self.build_epacls_dict_from_xml(service=self.service,
                                                          deployment=self.deployment,
                                                          name=self.name)           
            if verbose: pprint.pprint(self.__dict__)
            
            if not self.readonly:
                try:
                    d = dict()
                    result = self.sms.update_role(self.service, self.deployment, self.name,
                                                  os_virtual_hard_disk=self.os_disk,
                                                  network_config=self.net_config,
                                                  availability_set_name=self.availset,
                                                  data_virtual_hard_disks=self.data_disks,
                                                  role_size=self.size,
                                                  role_type='PersistentVMRole',
                                                  resource_extension_references=self.rextrs,
                                                  provision_guest_agent=True)
                    d['result'] = result.__dict__
                    if not self.async:
                        operation = self.sms.get_operation_status(result.request_id)
                        d['operation'] = operation.__dict__
                        d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                        self.wait_for_vm_provisioning_completion({'service': self.service,
                                                                  'deployment': self.deployment,
                                                                  'name': self.name})
                        
                        pprint.pprint(self.set_epacls({'service': self.service,
                                                       'deployment': self.deployment,
                                                       'name': self.name,
                                                       'epacls': self.epacls,
                                                       'subnet': self.subnet}))                           
                        return d
                    else:
                        return d
                except (WindowsAzureConflictError) as e:
                    logger('%s: operation in progress or resource exists, try again..' % inspect.stack()[0][3])
                    return False
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])                
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def update_storage_account(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.account = self.get_params(key='account', params=arg, default=None)
            self.account_type = self.get_params(key='account_type', params=arg, default=None)
            self.label = self.get_params(key='label', params=arg, default=None)
            self.description = self.get_params(key='description', params=arg, default=None)
            self.extended_properties = self.get_params(key='extended_properties', params=arg, default=None)
            self.async = self.get_params(key='async', params=arg, default=None)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)

            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:                
                return self.sms.update_storage_account(self.account, self.description, self.label,
                                                       geo_replication_enabled=None,
                                                       extended_properties=self.extended_properties,
                                                       account_type=self.account_type)
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def update_vm_image(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.name = self.get_params(key='name', params=arg, default=None)
            if isinstance(self.name, list): self.name = self.name[0]            
            self.label = self.get_params(key='label', params=arg, default=self.name)
            self.description = self.get_params(key='label', params=arg, default=self.label)
            self.blob = self.get_params(key='blob', params=arg, default=None)
            self.account = self.get_params(key='account', params=arg, default=self.default_storage_account)
            self.os = self.get_params(key='os', params=arg, default=None)
            self.os_state = self.get_params(key='os_state', params=arg, default=self.default_os_state)
            self.host_caching = self.get_params(key='host_caching', params=arg, default=self.default_host_caching)
            self.language = self.get_params(key='language', params=arg, default=None)
            self.family = self.get_params(key='family', params=arg, default=None)
            self.disk_size = self.get_params(key='disk_size', params=arg, default=self.default_disk_size)
            self.size = self.get_params(key='size', params=arg, default=self.default_size)
            self.eula_uri = self.get_params(key='eula_uri', params=arg, default=None)
            self.icon_uri = self.get_params(key='icon_uri', params=arg, default=None)
            self.small_icon_uri = self.get_params(key='small_icon_uri', params=arg, default=None)
            self.show_in_gui = self.get_params(key='show_in_gui', params=arg, default=None)
            self.privacy_uri = self.get_params(key='privacy_uri', params=arg, default=None)
            self.async = self.get_params(key='async', params=arg, default=None)    
            self.readonly = self.get_params(key='readonly', params=arg, default=None)                
            verbose = self.get_params(key='verbose', params=arg, default=None)

            vm_image = VMImage()
            vm_image.name = self.name
            vm_image.label = self.label
            vm_image.description = self.description
            vm_image.eula = self.eula_uri
            vm_image.icon_uri = self.icon_uri
            vm_image.small_icon_uri = self.small_icon_uri
            vm_image.published_date = mkdate(datetime.now(), '%Y-%m-%d')
            vm_image.show_in_gui = self.show_in_gui
            vm_image.privacy_uri = self.privacy_uri

            media_link = 'https://%s.blob.core.windows.net/%s/%s' % (self.account,
                                                                     'vhds',
                                                                     self.blob[0])
            
            vm_image.os_disk_configuration = OSVirtualHardDisk()
            vm_image.os_disk_configuration.os = self.os
            vm_image.os_disk_configuration.os_state = self.os_state
            vm_image.os_disk_configuration.media_link = media_link
            vm_image.os_disk_configuration.host_caching = self.host_caching
            
            if len(self.blob) > 1:
                vm_image.data_disk_configurations = DataVirtualHardDisks()
                for i in range(1, len(self.blob)):
                    data_disk_configuration = DataVirtualHardDisk()
                    data_disk_configuration.logical_disk_size_in_gb = self.disk_size
                    media_link = 'https://%s.blob.core.windows.net/%s/%s' % (self.account,
                                                                             'images',
                                                                             self.blob[i])
                    data_disk_configuration.host_caching = self.host_caching
                    data_disk_configuration.lun = i
                    data_disk_configuration.media_link = media_link                 
                    vm_image.data_disk_configurations.data_virtual_hard_disks.append(data_disk_configuration)
            
            vm_image.language = self.language
            vm_image.image_family = self.family
            vm_image.recommended_vm_size = self.size
            self.vm_image = vm_image
            
            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                try:
                    d = dict()                    
                    result = self.sms.create_vm_image(self.name, self.vm_image)
                    d['result'] = result.__dict__
                    if not self.async:
                        operation = self.sms.get_operation_status(result.request_id)
                        d['operation'] = operation.__dict__
                        d['operation_result'] = self.wait_for_operation_status(request_id=result.request_id)
                        return d
                    else:
                        return 
                except (WindowsAzureConflictError) as e:
                    logger('%s: operation in progress or resource exists, try again..' % inspect.stack()[0][3])
                    return False
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def urlencode_sig_query_string_part(self, url):
        enc_sig = quote_plus(parse_qs(url)['sig'][0])
        enc_se = quote_plus(parse_qs(url)['se'][0])
        t = urlsplit(url)
        ql = []
        for q in t.query.split('&'):
            if q.startswith('sig='):
                ql.append('sig=' + enc_sig)                
            elif q.startswith('se='):
                ql.append('se=' + enc_se)
            else:
                ql.append(q)

        pl = [t.scheme, t.netloc, t.path, '&'.join(ql), '']
        return urlunsplit(pl)

    def verify_params(self, **kwargs):
        if not kwargs: return None
        params = kwargs['params']
        method = kwargs['method']
        for param in [p['params'] for p in self.actions if p['action'] == method][0]:
            if param not in params.keys() or params[param] is None or params[param] == '':
                logger('%s: not all required parameters %s validated, %s=%s' % (method,
                                                                                [p['params'] for p in self.actions if p['action'] == method][0],
                                                                                param,
                                                                                params[param]))
                return False
        return params

    def wait_for_operation_status(self, **kwargs):
        try:
            if not kwargs: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=kwargs)
            if not arg: return False
            
            self.request_id = self.get_params(key='request_id', params=arg, default=None)
            self.status = self.get_params(key='status', params=arg, default=self.default_status)                                         
            self.wait = self.get_params(key='wait_for_status', params=arg, default=self.default_wait)
            self.timeout = self.get_params(key='timeout', params=arg, default=self.default_timeout)
            verbose = self.get_params(key='verbose', params=arg, default=None)

            if verbose: pprint.pprint(self.__dict__)
                                                  
            return self.sms.wait_for_operation_status(self.request_id,
                                                      wait_for_status=self.status,
                                                      timeout=self.timeout,
                                                      sleep_interval=self.wait).__dict__
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def walk_upgrade_domain(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.upgrade_domain = self.get_params(key='upgrade_domain', params=arg, default=None)
            self.async = self.get_params(key='async', params=arg, default=None)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)

            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                return self.sms.walk_upgrade_domain(self.service, self.deployment, self.upgrade_domain)
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def wait_for_vm_provisioning_completion(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False
            
            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.name = self.get_params(key='name', params=arg, default=None)
            if isinstance(self.name, list): self.name = self.name[0]
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            verbose = self.get_params(key='verbose', params=arg, default=None)

            if verbose: pprint.pprint(self.__dict__)

            if not self.readonly:

                @retry(AssertionError, tries=5, delay=15, backoff=2, cdata='method=%s()' % inspect.stack()[0][3])
                def wait_for_vm_provisioning_completion_retry():                    
                    deployment = self.get_deployment_by_name({'service': self.service,
                                                              'deployment': self.deployment,
                                                              'verbose': False})
                    if 'role_instance_list' in deployment:
                        result = True
                        role_instances = deployment['role_instance_list']['role_instances']
                        if not isinstance(role_instances, list): role_instances = [role_instances]
                        for role_instance in role_instances:
                            if role_instance['role_name'] == self.name and role_instance['instance_status'] != 'ReadyRole':
                                logger('%s: role_name %s (%s) is currently %s' % (inspect.stack()[0][3],
                                                                                  role_instance['role_name'],
                                                                                  role_instance['host_name'],
                                                                                  role_instance['instance_status']))
                                result = False
                            elif role_instance['role_name'] == self.name and role_instance['instance_status'] == 'ReadyRole':
                                logger('%s: role_name %s (%s) is currently %s' % (inspect.stack()[0][3],
                                                                                  role_instance['role_name'],
                                                                                  role_instance['host_name'],
                                                                                  role_instance['instance_status']))
                        assert result
                        
                return wait_for_vm_provisioning_completion_retry()
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def x_ms_version(self):
        return self.sms.x_ms_version

if __name__ == '__main__':
    if BaseCloudHarnessClass.log: logging.basicConfig(filename=BaseCloudHarnessClass.log_file,
                                                      format='%(asctime)s %(message)s',
                                                      level=logging.INFO)
    arg = args()    
    if arg.provider in ['azure']:
        if arg.action == 'get_certificate_from_publish_settings':
            pprint.pprint(get_certificate_from_publish_settings(arg.publish_settings,
                                                                path_to_write_certificate=arg.certificate,
                                                                subscription_id=arg.subscription_id))
            sys.exit(0)
        
        az = AzureCloudClass(subscription_id=arg.subscription_id, management_certificate=arg.management_certificate)

        for action in az.actions:
            if action['action'] == arg.action and action['collection']:
                pprint.pprint(az.list_collection(arg.__dict__))
            elif action['action'] == arg.action and not action['collection']:
                method = getattr(az, arg.action)
                pprint.pprint(method(arg.__dict__))
    else:
        logger(message='unknown provider %s' % arg.provider)
