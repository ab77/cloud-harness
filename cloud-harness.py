#!/usr/bin/env python
# -*- coding: cp1252 -*-

'''
Version: 0.1
Author: Anton Belodedenko (anton@blinkbox.com)
Date: 16/06/2015
Name: Cloud Harness
Git: https://github.com/ab77/cloud-harness

Synopsis:
Python wrapper for cloud service provider APIs/SDKs, supporting:
- Azure Service Management using [Microsoft Azure Python SDK/API](https://github.com/Azure/azure-sdk-for-python)
'''

import time, sys, os, argparse, logging, json, pprint, ConfigParser, hashlib, string, inspect, traceback

from datetime import date, timedelta, datetime
from calendar import timegm
from random import SystemRandom, randint
from requests import Session
from xml.etree.ElementTree import Element, SubElement, tostring, fromstring
from base64 import b64encode
from urlparse import urlsplit, urlunsplit, parse_qs
from urllib import quote_plus
from functools import wraps

try:
    from azure import *
    from azure.servicemanagement import *
    from azure.storage import AccessPolicy
    from azure.storage.sharedaccesssignature import SharedAccessPolicy, SharedAccessSignature
except ImportError:
    sys.stderr.write('ERROR: Python module "azure" not found, please run "pip install azure".\n')
    sys.exit(1)

try:
    import xmltodict
except ImportError:
    sys.stderr.write('ERROR: Python module "xmltodict" not found, please run "pip install xmltodict".\n')
    sys.exit()

def mkdate(dt, format):
    return datetime.strftime(dt, format)

def recurse_dict(d):
    for k, v in d.iteritems():
        if isinstance(v, dict):
            recurse_dict(v)
    else:
        return v

defaultTries = 3
defaultDelay = 2
defaultBackoff = 2

def retry(ExceptionToCheck, tries=defaultTries, delay=defaultDelay, backoff=defaultBackoff, cdata=None):
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
    azure.add_argument('--certificate_path', type=str, required=False, default=AzureCloudClass.default_certificate_path, help='Azure management certificate (default: %s)' % AzureCloudClass.default_certificate_path)
    azure.add_argument('--start_date', type=str, default=mkdate(AzureCloudClass.default_start_date, '%Y-%m-%d'), help='start date for list_subscription_operations (default: %s)' % mkdate(AzureCloudClass.default_start_date, '%Y-%m-%d'))
    azure.add_argument('--end_date', type=str, default=mkdate(AzureCloudClass.default_end_date, '%Y-%m-%d'), help='end date for subscription_operations (default: %s)' % mkdate(AzureCloudClass.default_end_date, '%Y-%m-%d'))
    azure.add_argument('--service', type=str, required=False, help='hosted service name')
    azure.add_argument('--account', type=str, required=False, default=BaseCloudHarnessClass.default_storage_account, help='storage account name (default: %s)' % BaseCloudHarnessClass.default_storage_account)
    azure.add_argument('--container', type=str, required=False, default=BaseCloudHarnessClass.default_storage_container, help='storage container name (default: %s)' % BaseCloudHarnessClass.default_storage_container)
    azure.add_argument('--group', type=str, required=False, help='affinity group name')
    azure.add_argument('--label', type=str, required=False, help='affinity group, disk or role name label')
    azure.add_argument('--description', type=str, required=False, help='affinity group description')
    azure.add_argument('--name', type=str, required=False, help='VM (role) or DNS server name')
    azure.add_argument('--ipaddr', type=str, required=False, help='DNS server IP address')
    azure.add_argument('--image', type=str, required=False, help='OS or data disk image blob name')
    azure.add_argument('--disk', type=str, required=False, help='disk name')
    azure.add_argument('--delete_vhds', action='store_true', required=False, help='delete VHDs')
    azure.add_argument('--delete_disks', action='store_true', required=False, help='delete disks')
    azure.add_argument('--async', action='store_true', required=False, help='asynchronous operation')
    azure.add_argument('--thumbprint', type=str, required=False, help='certificate thumbprint')    
    azure.add_argument('--request_id', type=str, required=False, help='request ID')    
    azure.add_argument('--status', type=str, required=False, default=AzureCloudClass.default_status, choices=['Succeeded', 'InProgress', 'Failed'], help='wait for operation status (default %r)' % AzureCloudClass.default_status)
    azure.add_argument('--wait', type=int, required=False, default=AzureCloudClass.default_wait, help='operation wait time (default %i)' % AzureCloudClass.default_wait)
    azure.add_argument('--timeout', type=int, required=False, default=AzureCloudClass.default_timeout, help='operation timeout (default %i)' % AzureCloudClass.default_timeout)
    azure.add_argument('--deployment', type=str, required=False, help='deployment name')
    azure.add_argument('--slot', type=str, required=False, default=AzureCloudClass.default_deployment_slot, help='deployment slot (default %s)' % AzureCloudClass.default_deployment_slot)
    azure.add_argument('--size', type=str, required=False, default=AzureCloudClass.default_size, help='VM size (default %s)' % AzureCloudClass.default_size)
    azure.add_argument('--disk_size', type=int, required=False, default=AzureCloudClass.default_disk_size, help='disk size in GB (default %s)' % AzureCloudClass.default_disk_size)
    azure.add_argument('--host_caching', type=str, required=False, default=AzureCloudClass.default_host_caching, choices=['ReadOnly', 'None', 'ReadOnly', 'ReadWrite'], help='wait for operation status (default %r)' % AzureCloudClass.default_host_caching)
    azure.add_argument('--username', type=str, required=False, default=AzureCloudClass.default_user_name, help='username for VM deployments (default %s)' % AzureCloudClass.default_user_name)
    azure.add_argument('--password', type=str, required=False, help='password for VM deployments')
    azure.add_argument('--pwd_expiry', type=int, required=False, default=AzureCloudClass.default_pwd_expiry, help='VMAccess password expiry (default: %i days)' % AzureCloudClass.default_pwd_expiry)
    azure.add_argument('--disable_pwd_auth', action='store_true', required=False, help='disable Linux password authentication')
    azure.add_argument('--ssh_auth', action='store_true', required=False, help='Linux SSH key authentication')
    azure.add_argument('--readonly', action='store_true', required=False, help='limit to read-only operations')
    azure.add_argument('--verbose', action='store_true', required=False, help='verbose output')
    azure.add_argument('--ssh_public_key_cert', type=str, required=False, default=AzureCloudClass.default_ssh_public_key_cert, help='Linux SSH certificate with public key path (default %s)' % AzureCloudClass.default_ssh_public_key_cert)
    azure.add_argument('--custom_data_file', type=str, required=False, help='custom data file')
    azure.add_argument('--algorithm', type=str, default=AzureCloudClass.default_algorithm, required=False, help='Thumprint algorithm (default %s)' % AzureCloudClass.default_algorithm)
    azure.add_argument('--os', type=str, required=False, choices=['Windows', 'Linux'], help='OS type')
    azure.add_argument('--availset', type=str, required=False, help='availability set name')
    azure.add_argument('--network', type=str, required=False, help='virtual network name')
    azure.add_argument('--subnet', type=str, required=False, help='subnet name')
    azure.add_argument('--lun', type=str, required=False, help='logical (disk) unit number (LUN)')
    azure.add_argument('--location', type=str, required=False, help='affinity group location')
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
    args = parser.parse_args()
    logger(message=str(args))
    return args

def logger(message=None):
    if BaseCloudHarnessClass.debug: sys.stderr.write('DEBUG %s\n' % repr(message))
    if BaseCloudHarnessClass.log: logging.info('%s\n' % repr(message))         

class BaseCloudHarnessClass():
    debug = True
    log = True
    proxy = True
    ssl_verify = False
    proxy_host = 'localhost'
    proxy_port = 8888
    log_file = '%s' % os.path.basename(__file__).replace('py', 'log')
    config_file = '%s' % os.path.basename(__file__).replace('py', 'conf')
    cp = ConfigParser.SafeConfigParser()        
    try:
        with open(config_file) as cf:
            cp.readfp(cf)
    except IOError:
        pass

    try:
        default_subscription_id = dict(cp.items('AzureConfig'))['default_subscription_id']
        default_certificate_path = dict(cp.items('AzureConfig'))['default_certificate_path']
        default_chef_server_url = dict(cp.items('ChefClient'))['default_chef_server_url']
        default_chef_validation_client_name = dict(cp.items('ChefClient'))['default_chef_validation_client_name']
        default_chef_validation_key_file = dict(cp.items('ChefClient'))['default_chef_validation_key_file']
        default_chef_run_list = dict(cp.items('ChefClient'))['default_chef_run_list']
        default_chef_autoupdate_client = dict(cp.items('ChefClient'))['default_chef_autoupdate_client']
        default_chef_delete_config = dict(cp.items('ChefClient'))['default_chef_delete_config']
        default_chef_ssl_verify_mode = dict(cp.items('ChefClient'))['default_chef_ssl_verify_mode']
        default_chef_verify_api_cert = dict(cp.items('ChefClient'))['default_chef_verify_api_cert']        
        default_windows_customscript_name = dict(cp.items('CustomScriptExtensionForWindows'))['default_windows_customscript_name']
        default_linux_customscript_name = dict(cp.items('CustomScriptExtensionForLinux'))['default_linux_customscript_name']
        default_remote_subnets = cp.items('DefaultEndpointACL')
        default_ssh_public_key_cert = dict(cp.items('LinuxConfiguration'))['default_ssh_public_key_cert']       
        default_ssh_public_key = dict(cp.items('LinuxConfiguration'))['default_ssh_public_key']
        default_linux_custom_data_file = dict(cp.items('LinuxConfiguration'))['default_linux_custom_data_file']
        default_windows_custom_data_file = dict(cp.items('WindowsConfiguration'))['default_windows_custom_data_file']
        default_storage_account = dict(cp.items('AzureConfig'))['default_storage_account']
        default_storage_container = dict(cp.items('AzureConfig'))['default_storage_container']
        default_patching_healthy_test_script = dict(cp.items('OSPatchingExtensionForLinux'))['default_patching_healthy_test_script']        
        default_patching_idle_test_script = dict(cp.items('OSPatchingExtensionForLinux'))['default_patching_idle_test_script']
    except (KeyError, ConfigParser.NoSectionError):
        default_chef_server_url = None
        default_chef_validation_client_name = None
        default_chef_validation_key_file = None
        default_chef_run_list = None
        default_windows_customscript_name = None
        default_linux_customscript_name = None
        default_remote_subnets = None
        default_ssh_public_key_cert = None
        default_ssh_public_key = None
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
        pass
    
class AzureCloudClass(BaseCloudHarnessClass):
    default_action = 'list_hosted_services'
    actions = [{'action': 'x_ms_version', 'params': [], 'collection': False},
               {'action': 'host', 'params': [], 'collection': False},
               {'action': 'cert_file', 'params': [], 'collection': False},
               {'action': 'content_type', 'params': [], 'collection': False},
               {'action': 'timeout', 'params': [], 'collection': False},
               {'action': 'sub_id', 'params': [], 'collection': False},
               {'action': 'request_session', 'params': [], 'collection': False},
               {'action': 'requestid', 'params': [], 'collection': False},
               {'action': 'list_collection', 'params': ['action'], 'collection': False},
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
               {'action': 'add_resource_extension', 'params': ['deployment', 'service', 'name', 'extension'], 'collection': False},
               {'action': 'add_role', 'params': ['deployment', 'service', 'os', 'name', 'image', 'subnet', 'account'], 'collection': False},
               {'action': 'add_data_disk', 'params': ['service', 'deployment', 'name'], 'collection': False},
               {'action': 'add_disk', 'params': [], 'collection': False},
               {'action': 'add_dns_server', 'params': [], 'collection': False},
               {'action': 'add_management_certificate', 'params': [], 'collection': False},
               {'action': 'add_os_image', 'params': [], 'collection': False},
               {'action': 'add_service_certificate', 'params': [], 'collection': False},
               {'action': 'build_epacls_dict_from_xml', 'params': ['deployment', 'service', 'name'], 'collection': False},
               {'action': 'build_chefclient_resource_extension', 'params': ['os'], 'collection': False},
               {'action': 'build_customscript_resource_extension', 'params': ['os'], 'collection': False},
               {'action': 'build_vmaccess_resource_extension', 'params': ['os'], 'collection': False},
               {'action': 'build_ospatching_resource_extension', 'params': ['os'], 'collection': False},
               {'action': 'build_resource_extension_dict', 'params': ['os', 'extension', 'publisher', 'version'], 'collection': False},
               {'action': 'build_resource_extensions_xml_from_dict', 'params': ['extensions'], 'collection': False},
               {'action': 'check_hosted_service_name_availability', 'params': [], 'collection': False},
               {'action': 'check_storage_account_name_availability', 'params': [], 'collection': False},
               {'action': 'create_affinity_group', 'params': [], 'collection': False},
               {'action': 'create_virtual_machine_deployment', 'params': [], 'collection': False},
               {'action': 'change_deployment_configuration', 'params': [], 'collection': False},
               {'action': 'capture_role', 'params': [], 'collection': False},
               {'action': 'capture_vm_image', 'params': [], 'collection': False},
               {'action': 'delete_affinity_group', 'params': [], 'collection': False},
               {'action': 'delete_role', 'params': ['deployment', 'service', 'name'], 'collection': False},
               {'action': 'delete_disk', 'params': ['disk'], 'collection': False},
               {'action': 'delete_deployment', 'params': [], 'collection': False},
               {'action': 'delete_dns_server', 'params': [], 'collection': False},
               {'action': 'get_certificate_from_publish_settings', 'params': [], 'collection': False},
               {'action': 'get_storage_account_properties', 'params': [], 'collection': False},
               {'action': 'get_deployment_by_slot', 'params': [], 'collection': False},
               {'action': 'get_deployment_by_name', 'params': [], 'collection': False},
               {'action': 'get_role', 'params': [], 'collection': False},
               {'action': 'get_data_disk', 'params': [], 'collection': False},
               {'action': 'get_disk', 'params': [], 'collection': False},
               {'action': 'get_hosted_service_properties', 'params': [], 'collection': False},
               {'action': 'get_management_certificate', 'params': [], 'collection': False},
               {'action': 'get_operation_status', 'params': [], 'collection': False},
               {'action': 'get_os_image', 'params': [], 'collection': False},
               {'action': 'get_reserved_ip_address', 'params': [], 'collection': False},
               {'action': 'get_service_certificate', 'params': [], 'collection': False},
               {'action': 'get_storage_account_keys', 'params': [], 'collection': False},
               {'action': 'get_subscription', 'params': [], 'collection': False},
               {'action': 'get_affinity_group_properties', 'params': [], 'collection': False},
               {'action': 'get_hosted_service_properties', 'params': [], 'collection': False},
               {'action': 'get_disk_by_role_name', 'params': ['service', 'deployment', 'name'], 'collection': False},
               {'action': 'get_os_for_role', 'params': ['deployment', 'service', 'name'], 'collection': False},
               {'action': 'get_objs_for_role', 'params': ['deployment', 'service', 'name'], 'collection': False},
               {'action': 'generate_signed_blob_url', 'params': ['account', 'container', 'script'], 'collection': False},
               {'action': 'perform_get', 'params': ['path'], 'collection': False},
               {'action': 'perform_put', 'params': ['path', 'body'], 'collection': False},
               {'action': 'perform_delete', 'params': ['path'], 'collection': False},
               {'action': 'perform_post', 'params': ['path', 'body'], 'collection': False},
               {'action': 'set_epacls', 'params': ['service', 'deployment', 'name', 'subnet'], 'collection': False},
               {'action': 'get_epacls', 'params': ['service', 'deployment', 'name'], 'collection': False},
               {'action': 'reboot_role_instance', 'params': [], 'collection': False},
               {'action': 'start_role', 'params': [], 'collection': False},
               {'action': 'start_roles', 'params': [], 'collection': False},
               {'action': 'restart_role', 'params': [], 'collection': False},
               {'action': 'rebuild_role_instance', 'params': [], 'collection': False},
               {'action': 'regenerate_storage_account_keys', 'params': [], 'collection': False},
               {'action': 'reimage_role_instance', 'params': [], 'collection': False},
               {'action': 'rollback_update_or_upgrade', 'params': [], 'collection': False},
               {'action': 'swap_deployment', 'params': [], 'collection': False},
               {'action': 'shutdown_role', 'params': [], 'collection': False},
               {'action': 'shutdown_roles', 'params': [], 'collection': False},
               {'action': 'update_affinity_group', 'params': [], 'collection': False},
               {'action': 'update_data_disk', 'params': [], 'collection': False},
               {'action': 'update_deployment_status', 'params': [], 'collection': False},
               {'action': 'update_disk', 'params': [], 'collection': False},
               {'action': 'update_dns_server', 'params': [], 'collection': False},
               {'action': 'update_hosted_service', 'params': [], 'collection': False},
               {'action': 'update_os_image', 'params': [], 'collection': False},
               {'action': 'update_role', 'params': ['deployment', 'service', 'name'], 'collection': False},
               {'action': 'update_storage_account', 'params': [], 'collection': False},
               {'action': 'update_vm_image', 'params': [], 'collection': False},
               {'action': 'upgrade_deployment', 'params': [], 'collection': False},
               {'action': 'wait_for_operation_status', 'params': [], 'collection': False},
               {'action': 'walk_upgrade_domain', 'params': [], 'collection': False},
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
    
    def __init__(self, subscription_id=None, certificate_path=None):
        self.service = None
        self.group = None
        self.label = None
        self.description = None
        self.name = None
        self.ipaddr = None
        self.image = None
        self.disk = None
        self.thumbprint = None
        self.request_id = None
        self.deployment = None
        self.password = None
        self.os = None
        self.availset = None
        self.network = None
        self.subnet = None
        self.lun = None
        self.location = None
        self.subscription_id = subscription_id or self.default_subscription_id
        self.certificate_path = certificate_path or self.default_certificate_path
        if not self.subscription_id or not self.certificate_path:
            logger('%s: requires a subscription_id and certificate_path' % inspect.stack()[0][3])
            sys.exit(1)
        else:
            self.sms = ServiceManagementService(self.subscription_id, self.certificate_path, request_session=self.set_proxy())

    def verify_params(self, **kwargs):
        if not kwargs: return None
        params = kwargs['params']
        method = kwargs['method']
        for param in [p['params'] for p in self.actions if p['action'] == method][0]:
            if param not in params.keys() or params[param] is None:
                logger('%s: not all required parameters %s validated, %s=%s' % (method,
                                                                                [p['params'] for p in self.actions if p['action'] == method][0],
                                                                                param,
                                                                                params[param]))
                return False
        return params

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

    def add_resource_extension(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.name = self.get_params(key='name', params=arg, default=None)
            self.extension = self.get_params(key='extension', params=arg, default=None)
            self.verbose = self.get_params(key='verbose', params=arg, default=None)

            self.os = self.get_os_for_role(service=self.service, deployment=self.deployment, name=self.name, verbose=False)
           
            if self.os:
                arg['os'] = self.os
                if self.extension == 'ChefClient':                    
                    self.rextrs = self.build_chefclient_resource_extension(arg)
                    return self.update_role(self.__dict__)
                elif self.extension == 'CustomScript':
                    self.rextrs = az.build_customscript_resource_extension(arg)
                    return self.update_role(self.__dict__)
                elif self.extension == 'VMAccessAgent':
                    self.rextrs = az.build_vmaccess_resource_extension(arg)
                    return self.update_role(self.__dict__)
                elif self.extension == 'OSPatching':
                    self.rextrs = az.build_ospatching_resource_extension(arg)
                    return self.update_role(self.__dict__)                
                else:
                    logger('%s: unsupported extension %s' % (inspect.stack()[0][3], self.extension))
            else:
                return False
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
            self.os = self.get_params(key='os', params=arg, default=None)
            self.image = self.get_params(key='image', params=arg, default=None)
            self.account = self.get_params(key='account', params=arg, default=None)
            self.subnet = self.get_params(key='subnet', params=arg, default=None)
            self.container = self.get_params(key='container', params=arg, default=self.default_storage_container)
            self.label = self.get_params(key='label', params=arg, default=self.name)
            self.availset = self.get_params(key='availset', params=arg, default=None)
            self.password = self.get_params(key='password', params=arg, default=''.join(SystemRandom().choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for _ in range(11)))
            self.slot = self.get_params(key='slot', params=arg, default=self.default_deployment_slot)            
            self.size = self.get_params(key='size', params=arg, default=self.default_size)
            self.username = self.get_params(key='username', params=arg, default=self.default_user_name)        
            self.eps = self.get_params(key='eps', params=arg, default=self.default_endpoints)
            self.rextrs = self.get_params(key='rextrs', params=arg, default=None)
            self.ssh_public_key_cert = self.get_params(key='ssh_public_key_cert', params=arg, default=self.default_ssh_public_key_cert)
            self.async = self.get_params(key='async', params=arg, default=None)    
            self.readonly = self.get_params(key='readonly', params=arg, default=None)                
            self.ssh_auth = self.get_params(key='ssh_auth', params=arg, default=None)                
            self.disable_pwd_auth = self.get_params(key='disable_pwd_auth', params=arg, default=None)
            self.verbose = self.get_params(key='verbose', params=arg, default=None)
 
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
                    h = hashlib.sha1()
                    try:
                        with open(self.ssh_public_key_cert, 'rb') as cf:
                            h.update(cf.read())
                    except IOError:
                        logger('%s: unable to read %s' % (inspect.stack()[0][3],
                                                          self.ssh_public_key_cert))
                        return False                        
                    ssh = SSH()
                    pks = PublicKeys()
                    pk = PublicKey()
                    pk.path = '/home/%s/.ssh/authorized_keys' % self.username
                    pk.fingerprint = h.hexdigest().upper()
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
            self.disk_config = OSVirtualHardDisk(source_image_name=self.image,
                                                 media_link=self.media_link,
                                                 host_caching=None,
                                                 disk_label=None,
                                                 disk_name=None,
                                                 os=None,
                                                 remote_source_image_link=None)
            
            if self.verbose: pprint.pprint(self.__dict__)            

            if not self.readonly:
                try:
                    d = dict()
                    result = self.sms.add_role(self.service, self.deployment, self.name,
                                               self.os_config, self.disk_config, network_config=self.net_config,
                                               availability_set_name=self.availset, data_virtual_hard_disks=None, role_size=self.size,
                                               role_type='PersistentVMRole', resource_extension_references=self.rextrs, provision_guest_agent=True,
                                               vm_image_name=None, media_location=None)
                    d['result'] = result.__dict__
                    if not self.async:
                        operation = self.sms.get_operation_status(result.request_id)
                        d['operation'] = operation.__dict__
                        d['operation_result'] = self.wait_for_operation_status(result.request_id)
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
            self.lun = self.get_params(key='lun',
                                                params=arg,
                                                default=len(self.get_disk_by_role_name(service=self.service,
                                                                                       deployment=self.deployment,
                                                                                       name=self.name)))
            self.image = self.get_params(key='image', params=arg, default=None)
            self.disk = self.get_params(key='disk', params=arg, default=None)
            self.label = self.get_params(key='disk_label', params=arg, default=None)
            self.account = self.get_params(key='account', params=arg, default=self.default_storage_account)
            self.container = self.get_params(key='container', params=arg, default=self.default_storage_container)       
            self.host_caching = self.get_params(key='host_caching', params=arg, default=self.default_host_caching)
            self.disk_size = self.get_params(key='disk_size', params=arg, default=self.default_disk_size)            
            self.async = self.get_params(key='async', params=arg, default=None)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            self.verbose = self.get_params(key='verbose', params=arg, default=None)

            ts = mkdate(datetime.now(), '%Y-%m-%d-%H-%M-%S-%f')
            if self.image:
                self.media_link = None
                self.source_media_link = 'https://%s.blob.core.windows.net/%s/%s' % (self.account,
                                                                                     self.container,
                                                                                     self.image)
            else:
                self.source_media_link = None
                self.media_link = 'https://%s.blob.core.windows.net/%s/%s-%s-%s-%s.vhd' % (self.account,
                                                                                           self.container,
                                                                                           self.service,
                                                                                           self.disk,
                                                                                           ts,
                                                                                           self.lun)
            if self.verbose: pprint.pprint(self.__dict__)

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
                        d['operation_result'] = self.wait_for_operation_status(result.request_id)
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
        
    def add_disk(self):
        pass
        
    def add_dns_server(self, service=None, deployment=None, name=None, ipaddr=None):
        try:
            if service and deployment and name and ipaddr:
                self.service = service
                self.deployment = deployment
                self.name = name
                self.ipaddr = ipaddr
                result = self.sms.add_dns_server(self.service, self.deployment, self.name, self.ipaddr)        
                if result is not None:
                    d = dict()
                    operation = self.sms.get_operation_status(result.request_id)
                    d['result'] = result.__dict__
                    d['operation'] = operation.__dict__
                    return d
                else:
                    return False
            else:
               logger('add_dns_server() requires service, deployment, DNS server names and IP address, None specified') 
               sys.exit(1)
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
    
    def add_management_certificate(self):
        pass
    
    def add_os_image(self):
        pass
    
    def add_service_certificate(self):
        pass
        
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
                rexts = self.list_resource_extension_versions(self.__dict__)
                version = None
                for rext in rexts:
                    version = rext['version']                
                self.version = version.split('.')[0] + '.*'
                rext = self.build_resource_extension_dict(os=self.os, extension=self.extension, publisher=self.publisher, version=self.version,
                                                          pub_config_key=pub_config_key, pri_config_key=pub_config_key,
                                                          pub_config=pub_config, pri_config=pri_config)
            if self.os == 'Linux':
                self.extension = 'LinuxChefClient'
                rexts = self.list_resource_extension_versions(self.__dict__)
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
            self.container = 'customscripts'
                   
            pub_config = dict()
            pub_config_key = 'CustomScriptExtensionPublicConfigParameter'
            if self.os == 'Windows':
                self.script = self.get_params(key='script', params=arg, default=self.default_windows_customscript_name)
                pub_config['fileUris'] = ['%s' % self.generate_signed_blob_url(account=self.account,
                                                                               container=self.container,
                                                                               script=self.script)]
                self.extension = 'CustomScriptExtension'
                self.publisher = 'Microsoft.Compute'
                rexts = self.list_resource_extension_versions(self.__dict__)
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
                self.extension = 'CustomScriptForLinux'
                self.publisher = 'Microsoft.OSTCExtensions'
                rexts = self.list_resource_extension_versions(self.__dict__)
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
                pri_config['storageAccountKey'] = self.get_storage_account_keys(account=self.account)['storage_service_keys']['primary']
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
            self.ssh_public_key = self.get_params(key='ssh_public_key', params=arg, default=self.default_ssh_public_key)
            self.pwd_expiry = self.get_params(key='pwd_expiry', params=arg, default=self.default_pwd_expiry)

            pub_config = dict()
            pri_config = dict() 
            if self.os == 'Windows':                   
                pub_config_key = 'VMAccessAgentPublicConfigParameter'
                pri_config_key = 'VMAccessAgentPrivateConfigParameter'
                self.extension = 'VMAccessAgent'
                self.publisher = 'Microsoft.Compute'
                rexts = self.list_resource_extension_versions(self.__dict__)
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
                rexts = self.list_resource_extension_versions(self.__dict__)
                version = None
                for rext in rexts:
                    version = rext['version']          
                self.version = version.split('.')[0] + '.*'
                pub_config['timestamp'] = '%s' % timegm(time.gmtime())
                with open(self.ssh_public_key, 'rb') as cf:
                    ssh_cert = cf.read()                        
                if self.vmaop == 'ResetSSHKey':
                    pri_config['username'] = self.username
                    pri_config['ssh_key'] = ssh_cert
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
                        pri_config['ssh_key'] = ssh_cert
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
                rexts = self.list_resource_extension_versions(self.__dict__)
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
                pri_config['storageAccountKey'] = self.get_storage_account_keys(account=self.account)['storage_service_keys']['primary']
                rext = self.build_resource_extension_dict(os=self.os, extension=self.extension, publisher=self.publisher, version=self.version,
                                                          pub_config_key=pub_config_key, pub_config=pub_config,
                                                          pri_config_key=pri_config_key, pri_config=pri_config)
            return self.build_resource_extensions_xml_from_dict(extensions=rext[self.os])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def build_dsc_resource_extension(self):
        pass

    def build_docker_resource_extension(self):
        pass
    
    def build_logcollector_resource_extension(self):
        pass
    
    def build_vsreleasemanager_resource_extension(self):
        pass
    
    def build_vsremotedebug_resource_extension(self):
        pass
    
    def build_octopusdeploy_resource_extension(self):
        pass
    
    def build_puppet_resource_extension(self):
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

    def check_hosted_service_name_availability(self, service=None):
        if service:
            self.service = service
            result = self.sms.check_hosted_service_name_availability(self.service)
            return result.__dict__
        else:
            logger('check_hosted_service_name_availability() requires a service name, None specified')

    def check_storage_account_name_availability(self, account=None):
        try:
            if account:
                self.account = account
                result = self.sms.check_storage_account_name_availability(self.account)
                return result.__dict__
            else:
                logger('check_storage_account_name_availability() requires a storage account name, None specified')
                sys.exit(1)
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
        
    def create_affinity_group(self, group=None, label=None, description=None, location=None):
        try: 
            if group and label and location:
                self.group = group
                self.label = label
                self.description = description
                self.location = location
                result = self.sms.create_affinity_group(name=self.group,
                                                        label=self.label,
                                                        location=self.location,
                                                        description=self.description)
                return True
            else:
                logger('create_affinity_group() requires a name, label and location, None specified')
                sys.exit(1)
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def create_virtual_machine_deployment(self, deployment=None, service=None, slot=None,
                 label=None, size=None, os=None, availset=None,
                 network=None, rextrs=None, name=None,
                 username=None, password=None, image=None,
                 subnet=None, account=None, eps=None, async=None):
        pass

    def capture_role(self):
        pass
    
    def capture_vm_image(self):
        pass

    def create_deployment(self):
        pass

    def create_hosted_service(self, service=None, label=None, description=None,
                              location=None, affinity_group=None, extended_properties=None):
        pass
    
    def create_reserved_ip_address(self):
        pass
    
    def create_storage_account(self):
        pass
    
    def create_vm_image(self):
        pass

    def delete_affinity_group(self, group=None):
        if group:
            self.group = group
            try:
                result = self.sms.delete_affinity_group(self.group)
            except Exception as e:
                logger(message=traceback.print_exc())
                return False
            return True
        else:
            logger('delete_affinity_group() requires a group name, None specified')

    def delete_role(self, *args):        
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.name = self.get_params(key='name', params=arg, default=None)     
            self.service = self.get_params(key='service', params=arg, default=None)     
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.async = self.get_params(key='async', params=arg, default=None)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            self.delete_disks = self.get_params(key='delete_disks', params=arg, default=None)
            self.delete_vhds = self.get_params(key='delete_vhds', params=arg, default=None)
            self.verbose = self.get_params(key='verbose', params=arg, default=None)

            d = dict()
            d['disks'] = self.get_disk_by_role_name(self.__dict__) 

            if self.verbose: pprint.pprint(self.__dict__)

            if not self.readonly:
                result = self.sms.delete_role(self.service, self.deployment, self.name)
                d['result'] = result.__dict__
                if not self.async:
                    operation = self.sms.get_operation_status(result.request_id)
                    d['result'] = result.__dict__
                    d['operation'] = operation.__dict__
                    d['operation_result'] = self.wait_for_operation_status(result.request_id)
                    if self.delete_disks:
                        for disk in d['disks']:
                            d['delete_disks'] = list()
                            logger(message='%s: deleting disk %s attached to %s' % (inspect.stack()[0][3],
                                                                                    disk['name'],
                                                                                    disk['attached_to']))
                            args = {'disk': disk['name'],
                                    'delete_vhds': self.delete_vhds,
                                    'readonly': self.readonly,
                                    'verbose': self.verbose}
                            d['delete_disks'] = {'result': self.delete_disk(args), 'disk': disk['Name']}
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
            self.verbose = self.get_params(key='verbose', params=arg, default=None)

            if self.verbose: pprint.pprint(self.__dict__)

            if not self.readonly:

                @retry(WindowsAzureConflictError, tries=3, delay=10, backoff=2, cdata='method=%s()' % inspect.stack()[0][3])
                def delete_disk_retry():
                    return self.sms.delete_disk(self.disk, delete_vhd=self.delete_vhds)
                
                return delete_disk_retry()
            else:
                logger('%s: limited to read-only operations' % inspect.stack()[0][3])
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
    
    def delete_dns_server(self, service=None, deployment=None, name=None):
        try:
            if service and deployment and name:
                self.service = service
                self.deployment = deployment
                self.name = name
                result = self.sms.delete_dns_server(self.service, self.deployment, self.name)        
                if result is not None:
                    d = dict()
                    operation = self.sms.get_operation_status(result.request_id)
                    d['result'] = result.__dict__
                    d['operation'] = operation.__dict__
                    return d
                else:
                    return False
            else:
               logger('delete_dns_server() requires service, deployment and DNS server names, None specified') 
               sys.exit(1)
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
    
    def delete_hosted_service(self):
        pass
    
    def delete_management_certificate(self):
        pass
    
    def delete_os_image(self):
        pass
    
    def delete_reserved_ip_address(self):
        pass
    
    def delete_role_instances(self):
        pass
    
    def delete_service_certificate(self):
        pass
    
    def delete_storage_account(self):
        pass
    
    def delete_vm_image(self):
        pass
    
    def delete_data_disk(self):
        pass
    
    def delete_deployment(self, service=None, deployment=None, delete_vhds=None):
        try:
            if service and deployment:
                self.service = service
                self.deployment = deployment
                self.delete_vhds = delete_vhds
                result = self.sms.delete_deployment(self.service, self.deployment, delete_vhds=self.delete_vhds)
                return True
            else:
               logger('delete_deployment() requires service and deployment names, None specified') 
               sys.exit(1)
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def generate_signed_blob_url(self, **kwargs):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False
            
            self.account = self.get_params(key='account', params=arg, default=None)
            self.container = self.get_params(key='container', params=arg, default=None)
            self.script = self.get_params(key='script', params=arg, default=None)

            key = self.get_storage_account_keys(account=account)['storage_service_keys']['primary']       
            sas = SharedAccessSignature(account_name=self.account,account_key=key)
            ap = AccessPolicy()
            ap.expiry = (datetime.now() + timedelta(days=1)).strftime('%Y-%m-%dT%H:%S:%MZ')
            ap.permission = 'r'
            sap = SharedAccessPolicy(ap)
            path = '/%s/%s' % (container, script)                
            query = sas.generate_signed_query_string(path, 'b', sap)
            url = 'https://%s.blob.core.windows.net%s?%s' % (self.account, path, query)
            return self.urlencode_sig_query_string_part(url)               
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def get_certificate_from_publish_settings(self):
        subscription_id = get_certificate_from_publish_settings(publish_settings_path='MyAccount.PublishSettings',
                                                                path_to_write_certificate=self.default_certificate_path,
                                                                subscription_id=self.subscription_id)
        return subscription_id

    def get_storage_account_properties(self, account=None):        
        try:            
            if account:
                self.account = account
                account = self.sms.get_storage_account_properties(self.account)
                d = account.__dict__
                d['storage_service_properties'] = account.storage_service_properties.__dict__
                return d
            else:
                logger('get_storage_account_properties() requires a storage account name, None specified')
                sys.exit(1)
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def get_affinity_group_properties(self, group=None):
        try:            
            if group:
                self.group = group
                group = self.sms.get_affinity_group_properties(self.group)
                d = group.__dict__
                d['hosted_services'] = group.hosted_services.__dict__
                d['storage_services'] = group.storage_services.__dict__
                return d
            else:
                logger('get_affinity_group_properties() requires a group name, None specified')
                sys.exit(1)
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def get_deployment_by_name(self, service=None, deployment=None):
        try:
            if service and deployment:
                self.service = service
                self.deployment = deployment            
                deployment = self.sms.get_deployment_by_name(self.service, self.deployment)
                d = deployment.__dict__    
                return d
            else:
               logger('get_deployment_by_name() requires service and deployment names, None specified') 
               sys.exit(1)
        except Exception as e:
            logger(message=traceback.print_exc())
            return False    
    
    def get_deployment_by_slot(self, service=None, slot=None):
        try:
            if service:
                self.service = service
                if not slot: slot = self.default_deployment_slot
                self.slot = slot                
                deployment = self.sms.get_deployment_by_slot(self.service, self.slot)
                d = deployment.__dict__    
                return d
            else:
               logger('get_deployment_by_slot() requires a service name, None specified') 
               sys.exit(1)
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def get_data_disk(self, service=None, deployment=None, name=None, lun=None):
        try:
            if service and deployment and name:
                self.service = service                
                self.deployment = deployment
                self.name = name
                self.lun = lun
                disk = self.sms.get_data_disk(self.service, self.deployment, self.name, self.lun)
                d = disk.__dict__
                return d
            else:
               logger('get_data_disk() requires service, deployment and role names, None specified') 
               sys.exit(1)
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
    
    def get_disk(self, disk=None):
        try:
            if disk:
                self.disk = disk                
                role = self.sms.get_disk(self.disk)
                d = role.__dict__
                return d
            else:
               logger('get_disk() requires a disk name, None specified') 
               sys.exit(1)
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def get_hosted_service_properties(self, service, embed_detail=False):
        try:
            if service:
                self.service = service                
                service = self.sms.get_hosted_service_properties(self.service)
                d = service.__dict__
                return d
            else:
               logger('get_hosted_service_properties() requires a service name, None specified') 
               sys.exit(1)
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def get_management_certificate(self, thumbprint=None):
        try:
            if thumbprint:
                self.thumbprint = thumbprint                
                thumbprint = self.sms.get_management_certificate(self.thumbprint)
                d = thumbprint.__dict__
                return d
            else:
               logger('get_management_certificate() requires a certificate thumbprint, None specified')
               sys.exit(1)
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
        
    def get_operation_status(self, request_id=None):
        try:
            if request_id:
                self.request_id = request_id                
                operation = self.sms.get_operation_status(self.request_id)
                d = operation.__dict__
                if d['error']: d['error'] = operation.error.__dict__
                return d
            else:
                logger('get_operation_status() requires a request ID, None specified')
                sys.exit(1)
        except Exception as e:
            logger(message=traceback.print_exc())
            return False        

    def get_os_image(self):
        pass

    def get_reserved_ip_address(self):
        pass

    def get_service_certificate(self, service=None, algorithm=None, thumbprint=None):
        try:
            self.service = (service if service else None)
            self.algorithm = (algorithm if algorithm else self.default_algorithm)
            self.thumbprint = (thumbprint if thumbprint else None)            
            if self.service and self.algorithm and self.thumbprint:
                result = self.sms.get_service_certificate(self.service, self.algorithm, self.thumbprint)
                return result.__dict__
            else:
                logger('get_service_certificate() requires service, algorithm and thumbprint, None specified')
                sys.exit(1)
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
        
    def get_storage_account_keys(self, account=None):
        try:
            self.account = (account if account else None)          
            if self.account:
                result = self.sms.get_storage_account_keys(self.account)
                d = result.__dict__
                d['storage_service_keys'] = result.storage_service_keys.__dict__
                return d
            else:
                logger('get_storage_account_keys() requires a storage account name, None specified')
                sys.exit(1)
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def get_subscription(self):
        pass

    def get_disk_by_role_name(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False
            
            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.name = self.get_params(key='name', params=arg, default=None)
            
            self.action = 'list_disks'            
            disks = self.list_collection(self.__dict__)
            
            try:
                d = [k for k in disks if k is not None and k['attached_to']['role_name'] == self.name and k['attached_to']['deployment_name'] == self.deployment and k['attached_to']['hosted_service_name'] == self.service]
            except TypeError:
                d = None
                pass
            if d is not None:
                return d
            else:
                return None
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

            method = getattr(self.sms, self.action)
            results = method()
            l = []
            for item in results:
                l.append(self.dict_from_response_obj(item))
            return l
        except Exception as e:
            logger(message=traceback.print_exc())
            return False        

    def perform_get(self, path=None):
        try:
            if path:
                self.path = path
                response = self.sms.perform_get(self.path, x_ms_version=self.sms.x_ms_version)        
                if response is not None:
                    return response.__dict__
                else:
                    return None
            else:
               logger('perform_get() requires URL path, None specified') 
               sys.exit(1)
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def perform_delete(self, path=None):
        try:
            if path:
                self.path = path
                response = self.sms.perform_delete(self.path, x_ms_version=self.sms.x_ms_version)        
                if response is not None:
                    return response.__dict__
                else:
                    return None
            else:
               logger('perform_delete() requires URL path, None specified') 
               sys.exit(1)
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
    
    def perform_post(self, path=None, body=None):
        try:
            if path and body:
                self.path = path
                response = self.sms.perform_post(self.path, self.body, x_ms_version=self.sms.x_ms_version)        
                if response is not None:
                    return response.__dict__
                else:
                    return None
            else:
               logger('perform_post() requires URL path and body, None specified') 
               sys.exit(1)
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
    
    def perform_put(self, path=None, body=None):
        try:
            if path and body:
                self.path = path
                self.body = body
                response = self.sms.perform_put(self.path, self.body, x_ms_version=self.sms.x_ms_version)        
                if response is not None:
                    return response.__dict__
                else:
                    return None
            else:
               logger('perform_put() requires URL path and body, None specified') 
               sys.exit(1)
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def rebuild_role_instance(self):
        pass
    
    def regenerate_storage_account_keys(self):
        pass
    
    def reimage_role_instance(self):
        pass
    
    def rollback_update_or_upgrade(self):
        pass
    
    def reboot_role_instance(self, service=None, deployment=None, name=None):
        try:
            if service and deployment and name:
                self.service = service
                self.deployment = deployment
                self.name = name
                result = self.sms.reboot_role_instance(self.service, self.deployment, self.name)
                d = dict()
                operation = self.sms.get_operation_status(result.request_id)
                d['result'] = result.__dict__
                d['operation'] = operation.__dict__
                return d
            else:
               logger('reboot_role_instance() requires service, deployment and role names, None specified') 
               sys.exit(1)
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
    
    def start_role(self, service=None, deployment=None, name=None):
        try:
            if service and deployment and name:
                self.service = service
                self.deployment = deployment
                self.name = name
                result = self.sms.start_role(self.service, self.deployment, self.name)
                d = dict()
                operation = self.sms.get_operation_status(result.request_id)
                d['result'] = result.__dict__
                d['operation'] = operation.__dict__
                return d
            else:
               logger('start_role() requires service, deployment and role names, None specified') 
               sys.exit(1)
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
    
    def start_roles(self, service=None, deployment=None, names=None):
        try:
            if service and deployment and names:
                self.service = service
                self.deployment = deployment
                self.names = names
                result = self.sms.start_roles(self.service, self.deployment, self.names)
                d = dict()
                operation = self.sms.get_operation_status(result.request_id)
                d['result'] = result.__dict__
                d['operation'] = operation.__dict__
                return d
            else:
               logger('start_roles() requires service, deployment names and role names iterable, None specified') 
               sys.exit(1)
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
                             
    def restart_role(self, service=None, deployment=None, name=None):
        try:
            if service and deployment and name:
                self.service = service
                self.deployment = deployment
                self.name = name
                result = self.sms.restart_role(self.service, self.deployment, self.name)
                d = dict()
                operation = self.sms.get_operation_status(result.request_id)
                d['result'] = result.__dict__
                d['operation'] = operation.__dict__
                return d
            else:
               logger('restart_role() requires service, deployment and role names, None specified') 
               sys.exit(1)
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def request_session(self):
        return self.sms.request_session
    
    def requestid(self):        
        return self.sms.requestid

    def set_proxy(self):
        if self.proxy:
            s = Session()
            s.cert = self.default_certificate_path
            s.verify = self.ssl_verify
            s.proxies = {'http' : 'http://%s:%i' % (self.proxy_host, self.proxy_port),
                         'https': 'https://%s:%i' % (self.proxy_host, self.proxy_port)}
            return s
        else:
            return None

    def sub_id(self):
        return self.sms.subscription_id
    
    def shutdown_role(self, service=None, deployment=None, name=None):
        try:
            if service and deployment and name:
                self.service = service
                self.deployment = deployment
                self.name = name
                result = self.sms.shutdown_role(self.service, self.deployment, self.name)
                d = dict()
                operation = self.sms.get_operation_status(result.request_id)
                d['result'] = result.__dict__
                d['operation'] = operation.__dict__
                return d
            else:
               logger('shutdown_role() requires service, deployment and role names, None specified') 
               sys.exit(1)
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
                             
    def shutdown_roles(self, service=None, deployment=None, names=None):
        try:
            if service and deployment and names:
                self.service = service
                self.deployment = deployment
                self.names = names
                result = self.sms.shutdown_roles(self.service, self.deployment, self.names)
                d = dict()
                operation = self.sms.get_operation_status(result.request_id)
                d['result'] = result.__dict__
                d['operation'] = operation.__dict__
                return d
            else:
               logger('shutdown_roles() requires service, deployment names and role names iterable, None specified') 
               sys.exit(1)
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
   
    def swap_deployment(self):
        pass

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
            self.subnet = self.get_params(key='subnet', params=arg, default=None)
            self.verbose = self.get_params(key='verbose', params=arg, default=None)
            
            self.os = self.get_os_for_role(name=self.name, service=self.service, deployment=self.deployment, verbose=False)
            if not self.os: return False           

            self.epacls = self.get_params(key='epacls', params=arg, default=self.build_default_epacl_dict_for_os(os=self.os))

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
            if self.verbose: pprint.pprint(self.__dict__)

            self.async = self.get_params(key='async', params=arg, default=None)
            self.readonly = self.get_params(key='readonly', params=arg, default=None)
            
            if not self.readonly:
                d = dict()
                if not self.async:                  
                    d['result'] = self.perform_put(path=path, body=body)
                    request_id = [req_id[1] for req_id in d['result']['headers'] if req_id[0] == 'x-ms-request-id'][0]
                    operation = self.sms.get_operation_status(request_id)
                    d['operation'] = operation.__dict__
                    d['operation_result'] = self.wait_for_operation_status(request_id)
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
            d['operation_result'] = self.wait_for_operation_status(request_id)
            return d
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def timeout(self):
        return self.sms.timeout
    
    def upgrade_deployment(self):
        pass
    
    def change_deployment_configuration(self):
        pass

    def update_affinity_group(self, group=None, label=None, description=None):
        try:            
            if group and label:
                self.group = group
                self.label = label
                self.description = description
                group = self.sms.update_affinity_group(self.group,
                                                       self.label,
                                                       self.description)
                return True
            else:
                logger('update_affinity_group() requires a group name and label, None specified')
                sys.exit(1)
        except Exception as e:
            logger(message=traceback.print_exc())
            return False
    
    def update_data_disk(self):
        pass

    def update_deployment_status(self):
        pass

    def update_disk(self):
        pass

    def update_dns_server(self):
        pass

    def update_hosted_service(self):
        pass

    def update_os_image(self):
        pass

    def get_os_for_role(self, **kwargs):
        try:
            if not kwargs: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=kwargs)
            if not arg: return False
            
            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.name = self.get_params(key='name', params=arg, default=None)            

            role = self.get_role(service=self.service, deployment=self.deployment, name=self.name, verbose=False)
            if role:
                return role['os_virtual_hard_disk']['os']
            else:
                return None
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def get_role(self, **kwargs):
        try:
            if not kwargs: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=kwargs)
            if not arg: return False
            
            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.name = self.get_params(key='name', params=arg, default=None)
            
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
            self.key = self.get_params(key='key', params=arg, default=None)

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

    def dict_from_response_obj(self, *args):
        obj = args[0]
        
        if not isinstance(obj, dict):
            obj = self.dict_from_response_obj(obj.__dict__)

        for k, v in obj.iteritems():
            if '__dict__' in dir(v):
                obj[k] = v.__dict__
                obj = self.dict_from_response_obj(obj)
            if isinstance(v, dict):
                 v = recurse_dict(v)            
            if isinstance(v, list):                
                l = []
                for el in v:
                    if isinstance(el, unicode):
                        l.append(el)
                    elif not isinstance(el, dict):                      
                        l.append(el.__dict__)                        
                        obj[k] = l
        return obj

    def build_epacls_dict_from_xml(self, **kwargs):
        try:
            if not kwargs: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=kwargs)
            if not arg: return False
            
            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.name = self.get_params(key='name', params=arg, default=None)
            
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
        
    def update_role(self, *args):
        try:
            if not args: return False
            arg = self.verify_params(method=inspect.stack()[0][3], params=args[0])
            if not arg: return False

            self.service = self.get_params(key='service', params=arg, default=None)
            self.deployment = self.get_params(key='deployment', params=arg, default=None)
            self.name = self.get_params(key='name', params=arg, default=None)
            self.verbose = self.get_params(key='verbose', params=arg, default=None)

            role = self.get_role(service=self.service, deployment=self.deployment, name=self.name, verbose=False)
            role_objs = self.get_objs_for_role(service=self.service, deployment=self.deployment, name=self.name, verbose=False)
            
            if role and role_objs:
                self.os = self.get_params(key='os', params=arg, default=role['os_virtual_hard_disk']['os'])
                self.size = self.get_params(key='size', params=arg, default=role['role_size'])
                self.availset = self.get_params(key='availset', params=arg, default=role['availability_set_name'])
                self.subnet = self.get_params(key='subnet', params=arg, default=role['configuration_sets'][0]['subnet_names'][0])
                self.rextrs = self.get_params(key='rextrs', params=arg, default=None)
                self.eps = self.get_params(key='eps', params=arg, default=role['configuration_sets'][0]['input_endpoints'])
                self.os_disk = self.get_params(key='os_disk', params=arg, default=role_objs['os_virtual_hard_disk'])
                self.data_disks = self.get_params(key='data_disk', params=arg, default=role_objs['data_virtual_hard_disks'])
                self.async = self.get_params(key='async', params=arg, default=None) 
                self.readonly = self.get_params(key='readonly', params=arg, default=None)                
            else:
                logger('%s: unable to retrieve properties for role %s' % (inspect.stack()[0][3], self.name))
                return False
          
            net_config = ConfigurationSet()
            net_config.configuration_set_type = 'NetworkConfiguration'
            subnet = Subnet()
            subnet.name = self.subnet
            subnets = Subnets()
            subnets.subnets.append(subnet.name)
            net_config.subnet_names = subnets
            net_config.end = subnets
            net_config.input_endpoints = self.eps            
            self.net_config = net_config
                        
            if self.verbose: pprint.pprint(self.__dict__)
            
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
                        d['operation_result'] = self.wait_for_operation_status(result.request_id)
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
        
    def update_storage_account(self):
        pass

    def update_vm_image(self):
        pass

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
    
    def wait_for_operation_status(self, request_id=None, status=None, timeout=None, wait=None):
        try:
            if request_id:
                self.request_id = request_id
                self.status = status
                self.wait = wait
                self.timeout = timeout
                if status is None: self.status = self.default_status
                if wait is None: self.wait = self.default_wait
                if timeout is None: self.timeout = self.default_timeout
                result = self.sms.wait_for_operation_status(self.request_id,
                                                            wait_for_status=self.status,
                                                            timeout=self.timeout,
                                                            sleep_interval=self.wait)
                if result is not None:
                    return result.__dict__
                else:
                    return False
            else:
               logger('wait_for_operation_status() requires a request ID, None specified') 
               sys.exit(1)
        except Exception as e:
            logger(message=traceback.print_exc())
            return False

    def walk_upgrade_domain(self, service=None, deployment=None, upgrade_domain=None):
        pass

    def x_ms_version(self):
        return self.sms.x_ms_version
        
if __name__ == '__main__':
    if BaseCloudHarnessClass.log: logging.basicConfig(filename=BaseCloudHarnessClass.log_file, format='%(asctime)s %(message)s', level=logging.INFO)
    arg = args()
    if arg.provider in ['azure']:
        az = AzureCloudClass(subscription_id=arg.subscription_id, certificate_path=arg.certificate_path)

        for action in az.actions:            
            if action['action'] == arg.action and action['collection']:
                pprint.pprint(az.list_collection(arg))
                sys.exit(0)
        
        if arg.action in ['x_ms_version']: pprint.pprint(az.x_ms_version())
        elif arg.action in ['host']: pprint.pprint(az.host())
        elif arg.action in ['cert_file']: pprint.pprint(az.cert_file())
        elif arg.action in ['content_type']: pprint.pprint(az.content_type())
        elif arg.action in ['timeout']: pprint.pprint(az.timeout())
        elif arg.action in ['sub_id']: pprint.pprint(az.sub_id())
        elif arg.action in ['request_session']: pprint.pprint(az.request_session())
        elif arg.action in ['requestid']: pprint.pprint(az.requestid())
        elif arg.action in ['get_certificate_from_publish_settings']: az.get_certificate_from_publish_settings()
        elif arg.action in ['list_resource_extension_versions']: pprint.pprint(az.list_resource_extension_versions(arg.__dict__))
        elif arg.action in ['list_service_certificates']: pprint.pprint(az.list_service_certificates(arg.__dict__))
        elif arg.action in ['list_subscription_operations']: pprint.pprint(az.list_subscription_operations(arg.__dict__))
        elif arg.action in ['check_hosted_service_name_availability']: pprint.pprint(az.check_hosted_service_name_availability())
        elif arg.action in ['check_storage_account_name_availability']: pprint.pprint(az.check_storage_account_name_availability())
        elif arg.action in ['create_affinity_group']: pprint.pprint(az.create_affinity_group())
        elif arg.action in ['delete_affinity_group']: pprint.pprint(az.delete_affinity_group())
        elif arg.action in ['get_affinity_group_properties']: pprint.pprint(az.get_affinity_group_properties())
        elif arg.action in ['update_affinity_group']: pprint.pprint(az.update_affinity_group())
        elif arg.action in ['create_virtual_machine_deployment']: pprint.pprint(az.create_virtual_machine_deployment())
        elif arg.action in ['add_role']: pprint.pprint(az.add_role(arg.__dict__))
        elif arg.action in ['get_storage_account_properties']: pprint.pprint(az.get_storage_account_properties())
        elif arg.action in ['get_deployment_by_slot']: pprint.pprint(az.get_deployment_by_slot())
        elif arg.action in ['get_deployment_by_name']: pprint.pprint(az.get_deployment_by_name())
        elif arg.action in ['get_role']: pprint.pprint(az.get_role())
        elif arg.action in ['get_data_disk']: pprint.pprint(az.get_data_disk())
        elif arg.action in ['get_disk']: pprint.pprint(az.get_disk())
        elif arg.action in ['get_disk_by_role_name']: pprint.pprint(az.get_disk_by_role_name(arg.__dict__))
        elif arg.action in ['get_hosted_service_properties']: pprint.pprint(az.get_hosted_service_properties())        
        elif arg.action in ['get_management_certificate']: pprint.pprint(az.get_management_certificate())        
        elif arg.action in ['get_operation_status']: pprint.pprint(az.get_operation_status())
        elif arg.action in ['delete_role']: pprint.pprint(az.delete_role(arg.__dict__))
        elif arg.action in ['delete_disk']: pprint.pprint(az.delete_disk(arg.__dict__))
        elif arg.action in ['wait_for_operation_status']: pprint.pprint(az.wait_for_operation_status())
        elif arg.action in ['set_epacls']: pprint.pprint(az.set_epacls(arg.__dict__))
        elif arg.action in ['get_epacls']: pprint.pprint(az.get_epacls(arg.__dict__))
        elif arg.action in ['reboot_role_instance']: pprint.pprint(az.reboot_role_instance())
        elif arg.action in ['shutdown_role']: pprint.pprint(az.shutdown_role())
        elif arg.action in ['restart_role']: pprint.pprint(az.restart_role())
        elif arg.action in ['start_role']: pprint.pprint(az.start_role())
        elif arg.action in ['start_roles']: pprint.pprint(az.start_roles())
        elif arg.action in ['shutdown_roles']: pprint.pprint(az.shutdown_roles())
        elif arg.action in ['delete_dns_server']: pprint.pprint(az.delete_dns_server())
        elif arg.action in ['add_dns_server']: pprint.pprint(az.add_dns_server())
        elif arg.action in ['get_service_certificate']: pprint.pprint(az.get_service_certificate())
        elif arg.action in ['get_storage_account_keys']: pprint.pprint(az.get_storage_account_keys())
        elif arg.action in ['update_role']: pprint.pprint(az.update_role(arg.__dict__))
        elif arg.action in ['add_resource_extension']: pprint.pprint(az.add_resource_extension(arg.__dict__))
        elif arg.action in ['add_data_disk']: pprint.pprint(az.add_data_disk(arg.__dict__))
        else:
            logger(message='unknown action %s' % arg.action)
            sys.exit(1)
    else:
        logger(message='unknown provider %s' % arg.provider)
        sys.exit(1)
