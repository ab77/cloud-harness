## Cloud Harness
Python wrapper for cloud service provider APIs/SDKs.

### Supported Cloud Providers
Currently only one provider is supported:
* Azure Service Management using [Microsoft Azure Python SDK/API](https://github.com/Azure/azure-sdk-for-python)

### Installation and Configuration
* from a working Python environment, run `pip install azure && /opt && git clone https://github.com/ab77/cloud-harness.git && cd ./cloud-harness`
* copy cloud-harness.sample.conf to cloud-harness.conf
* [download](https://manage.windowsazure.com/publishsettings) and save your Azure PublishSettings file with `.publishsettings` extension
* run `./cloud-harness.py azure` for the first time to extract your management certificate and update the config file automatically (or [manually](http://stuartpreston.net/2015/02/retrieving-microsoft-azure-management-certificates-for-use-in-cross-platform-automationprovisioning-tools/) if you wish)
* set default `location_name` in `cloud-harness.conf` config file (e.g. East US)
* set other configuration properties as required in `cloud-harness.conf` config file (e.g. `storage_account`)

### General Usage
* run `python ./cloud-harness.py azure` for the default action `list_locations`
* run `python ./cloud-harness.py azure --help` to see all available command line options
* to get get a list of required parameters for a particular action (e.g. `add_role`), run `python ./cloud-harness.py azure --action add_role`
* specify `--verbose` flag to see various run-time properties
* specify `--readonly` flag to limit operations, which would otherwise perform changes (usually together with `--verbose`)

### Examples
Some useful examples to deploy virtual machines and resource extensions.

#### Create storage account (name must be unique as it forms part of the storage URL, check with `--action check_storage_account_name_availability`):

    ./cloud-harness.py azure --action create_storage_account \
    --account myuniquestorageaccountname01 \
    --verbose

#### Create a new hosted service (name must be unique within `cloudapp.net` domain, check with `--action check_storage_account_name_availability`):

    ./cloud-harness.py azure --action create_hosted_service \
    --service my-hosted-service \
    --label 'my hosted service' \
    --verbose

#### Add x.509 certificate containing RSA public key for SSH authentication to the hosted service:

    ./cloud-harness.py azure --action add_service_certificate \
    --service my-hosted-service \
    --certificate service_certificate.cer \
    --verbose

#### Create a reserved IP address for the hosted service:

    ./cloud-harness.py azure --action create_reserved_ip_address \
    --ipaddr my-reserved-ip-address \
    --verbose

#### Create Virtual Network:

    ./cloud-harness.py azure --action create_virtual_network_site \
	--network VNet1 \
	--dns google-primary google-secondary \
	--ipaddr 8.8.8.8 8.8.4.4 \
	--subnet Subnet-1 \
	--subnetaddr 10.0.0.0/11 \
	--vnetaddr 10.0.0.0/8 \
	--verbose

#### List OS Images:

    ./cloud-harness.py azure --action list_os_images
	
#### Create a new Linux virtual machine deployment and role with reserved IP and SSH authentication and wait for provisioning completion:

    ./cloud-harness.py azure --action create_virtual_machine_deployment \
    --service my-hosted-service \
    --deployment my-virtual-machine-deployment \
    --name my-ubuntu-virtual-machine \
    --label 'my deployment' \
    --account my-storage-account \
    --blob b39f27a8b8c64d52b05eac6a62ebad85__Ubuntu-14_04-LTS-amd64-server-20140724-en-us-30GB \
    --os Linux \
    --network my-virtual-network-name \
    --subnet my-subnet-name \
    --ipaddr my-reserved-ip-address \
    --size Medium \
    --ssh_auth \
    --disable_pwd_auth \
    --verbose

#### Add Google DNS servers to the virtual machine deployment:

    ./cloud-harness.py azure --action add_dns_server \
    --service my-hosted-service \
    --deployment my-virtual-machine-deployment \
    --dns google-primary \
    --ipaddr 8.8.8.8 \
    --verbose
    
    ./cloud-harness.py azure --action add_dns_server \
    --service my-hosted-service \
    --deployment my-virtual-machine-deployment \
    --dns google-secondary \
    --ipaddr 8.8.4.4  
    --verbose

#### Add `CustomScript` extension to the virtual machine, which will run `bootstrap.sh` to upgrade `WAAgent` as well as un-pack/execute `linux_custom_data.dat` where you can put additional bootstrap commands:

    ./cloud-harness.py azure --action add_resource_extension \
    --service my-hosted-service \
    --deployment my-virtual-machine-deployment \
    --name my-ubuntu-virtual-machine \
    --extension CustomScript \
    --verbose

#### Secure the virtual machine, by adding ACLs to the public facing SSH port:

    ./cloud-harness.py azure --action set_epacls \
    --service my-hosted-service \
    --deployment my-virtual-machine-deployment \
    --name my-ubuntu-virtual-machine \
    --subnet my-subnet-name \
    --verbose

#### Create a Linux virtual machine (role) with a random alpha-numeric password[n2] and wait for provisioning completion:

    ./cloud-harness.py azure --action add_role \
    --service my-hosted-service \
    --deployment my-virtual-machine-deployment \
    --name my-second-ubuntu-virtual-machine \
    --label 'my Linux (Ubuntu) virtual machine' \
    --account my-storage-account \
    --blob b39f27a8b8c64d52b05eac6a62ebad85__Ubuntu-14_04-LTS-amd64-server-20140724-en-us-30GB \
    --os Linux \
    --network my-virtual-network-name \
    --subnet my-subnet-name \
    --size Medium \
    --verbose

#### Add `CustomScript` extension to the Linux virtual machine:

    ./cloud-harness.py azure --action add_resource_extension \
    --service my-hosted-service \
    --deployment my-virtual-machine-deployment \
    --name my-second-ubuntu-virtual-machine \
    --extension CustomScript \
    --verbose

#### Add `ChefClient` extension to the Linux virtual machine[n2]:

    ./cloud-harness.py azure --action add_resource_extension \
    --service my-hosted-service \
    --deployment my-virtual-machine-deployment \
    --name my-second-ubuntu-virtual-machine \
    --extension ChefClient \
    --verbose

#### Add data disk to virtual machine:

    ./cloud-harness.py azure --action add_data_disk \
    --service my-hosted-service \
    --deployment my-virtual-machine-deployment \
    --name my-second-ubuntu-virtual-machine \
    --account my-storage-account \
    --verbose

#### Create a Windows virtual machine (role) with random alpha-numeric password and wait for provisioning completion:

    ./cloud-harness.py azure --action add_role \
    --service my-hosted-service \
    --deployment my-virtual-machine-deployment \
    --name my-windows-virtual-machine \
    --label 'my Windows 2K8R2 virtual machine' \
    --account my-storage-account \
    --os Windows \
    --blob a699494373c04fc0bc8f2bb1389d6106__Win2K8R2SP1-Datacenter-201505.01-en.us-127GB.vhd \
    --network my-virtual-network-name \
    --subnet my-subnet-name \
    --size Medium \
    --verbose

#### Add `CustomScript` extension to the Windows virtual machine, which will run `bootstrap.ps1` to un-pack/execute `windows_custom_data.dat` where you can put additional bootstrap commands:

    ./cloud-harness.py azure --action add_resource_extension \
    --service my-hosted-service \
    --deployment my-virtual-machine-deployment \
    --name my-windows-virtual-machine \
    --extension CustomScript \
    --verbose

#### Add `ChefClient` extension to the Linux virtual machine:

    ./cloud-harness.py azure --action add_resource_extension \
    --service my-hosted-service \
    --deployment my-virtual-machine-deployment \
    --name my-windows-virtual-machine \
    --extension ChefClient \
    --verbose

#### Add `Docker` extension to the Linux virtual machine:

    ./cloud-harness.py azure --action add_resource_extension \
    --service my-hosted-service \
    --deployment my-virtual-machine-deployment \
    --name my-second-ubuntu-virtual-machine \
    --extension DockerExtension \
    --verbose
	
#### Reset the Administrator password on the Windows VM using `VMAccess` extension:

    ./cloud-harness.py azure --action add_resource_extension \
    --service my-hosted-service \
    --deployment my-virtual-machine-deployment \
    --name my-second-ubuntu-virtual-machine \
    --extension VMAccessAgent \
    --password new-s3cure-passw0rd \
    --verbose

#### Update Linux virtual machine (role) using `OSPatching` extension:

    ./cloud-harness.py azure --action add_resource_extension \
    --service my-hosted-service \
    --deployment my-virtual-machine-deployment \
    --name my-second-ubuntu-virtual-machine \
    --extension OSPatching \
    --patching_oneoff \
    --verbose

#### **DESTROY** service, deployment, virtual machines (roles), disks and associated VHDs:

    ./cloud-harness.py azure --action delete_hosted_service \
    --service my-hosted-service \
    --delete_disks \
    --delete_vhds \
    --verbose

#### **DELETE** reserved IP address:

    ./cloud-harness.py azure --action delete_reserved_ip_address \
    --ipaddr my-reserved-ip-address

#### Fiddler Proxy
To use `Fiddler2` to capture HTTPS traffic to the API
* export your Azure Management Certificate as base64 encoded  x.509 as ClientCertificate.cer
* place it into your `Fiddler2` directory (e.g. `C:\Users\<user>\Documents\Fiddler2`)
* set `proxy = True` in `cloud-harness.conf` and re-launch `Fiddler2` [n1]

### Further Work
Lots, including:
* implement (at least) one additional cloud service provider
* add unittest framework
* implementat additional VM extensions
* move all defaults to config file

#### Notes
[n1] For more information, see [Using Fiddler to decipher Windows Azure PowerShell or REST API HTTPS traffic](http://blogs.msdn.com/b/avkashchauhan/archive/2013/01/30/using-fiddler-to-decipher-windows-azure-powershell-or-rest-api-https-traffic.aspx).

[n2] SSH authentication is not compatible with `ChefClient` extension due to the way it currently handles certificates [PR45](https://github.com/chef-partners/azure-chef-extension/pull/45).
