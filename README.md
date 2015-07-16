## Cloud Harness
Python wrapper for cloud service provider APIs/SDKs.

### Supported Cloud Providers
Currently only one provider is supported:
* Azure Service Management using [Microsoft Azure Python SDK/API](https://github.com/Azure/azure-sdk-for-python)

### Installation and Configuration
* from a working Python environment, run `pip install azure && /opt && git clone https://github.com/ab77/cloud-harness.git && cd ./cloud-harness`
* rename cloud-harness.sample.conf to cloud-harness.conf
* [download](https://manage.windowsazure.com/publishsettings) and save your Azure PublishSettings file as `MyAzure.publishsettings`
* edit `cloud-harness.conf` and set your `default_subscription_id` to match the one in the `PublishSettings` file
* [extract](http://stuartpreston.net/2015/02/retrieving-microsoft-azure-management-certificates-for-use-in-cross-platform-automationprovisioning-tools/) your Azure management certificate into PEM format from the `PublishSettings` file manually;
* or run `./cloud-harness.py azure --action get_certificate_from_publish_settings --publish_settings MyAzure.publishsettings --certificate management_certificate.pem` which will do it automatically
* uncomment other configuration options as required in `cloud-harness.conf`

### Usage
* run `python ./cloud-harness.py azure` for the default action `list_hosted_services`
* run `python ./cloud-harness.py azure --help` to see all available command line options
* to get get a list of required parameters for a particular action (e.g. `add_role`), run `python ./cloud-harness.py azure --action add_role`

### Examples
Some useful examples to deploy virtual machines and resource extensions.

Create a new hosted service:

    ./cloud-harness.py azure --action create_hosted_service \
    --service my-hosted-service --location 'West Europe' \
    --label 'my hosted service label'
    --verbose

Add x.509 certificate containing RSA public key for SSH authentication to the hosted service:

    ./cloud-harness.py azure --action add_service_certificate \
    --service my-hosted-service \
    --certificate service_certificate.cer
    --verbose

Create a reserved IP address for the hosted service:

    ./cloud-harness.py azure --action create_reserved_ip_address \
    --ipaddr my-reserved-ip-address \
    --location 'West Europe'
    --verbose

Create a new Linux virtual machine deployment with reserved IP and SSH authentication:

    ./cloud-harness.py azure --action create_virtual_machine_deployment \
    --service my-hosted-service \
    --deployment my-virtual-machine-deployment \
    --name my-ubuntu-virtual-machine \
    --label 'my deployment label' \
    --account my-storage-account \
    --blob b39f27a8b8c64d52b05eac6a62ebad85__Ubuntu-14_04-LTS-amd64-server-20140724-en-us-30GB \
    --os Linux \
    --network my-virtual-network-name \
    --subnet my-subnet-name \
    --ipaddr my-reserved-ip-address
    --size Medium \
    --ssh_auth \
    --disable_pwd_auth
    --verbose

Add Google DNS servers to the virtual machine deployment:

    ./cloud-harness.py azure --action add_dns_server \
    --service my-hosted-service \
    --deployment my-virtual-machine-deployment \
    --dns google-primary \
    --ipaddr 8.8.8.8
    --verbose

    ./cloud-harness.py azure --action add_dns_server \
    --service my-hosted-service \
    --deployment my-virtual-machine-deployment \
    --dns google-secondary \
    --ipaddr 8.8.4.4  
    --verbose

Add CustomScript extension to the virtual machine, which will run `bootstrap.sh` to upgrade `WAAgent` as well as un-pack/execute `linux_custom_data.dat`:

    ./cloud-harness.py azure --action add_resource_extension \
    --service my-hosted-service \
    --deployment my-virtual-machine-deployment \
    --name my-ubuntu-virtual-machine \
    --extension CustomScript
    --verbose

Secure the virtual machine, by adding ACLs to the public facing SSH port:

    ./cloud-harness.py azure --action set_epacls \
    --service my-hosted-service \
    --deployment my-virtual-machine-deployment \
    --name my-ubuntu-virtual-machine \
    --subnet my-subnet-name \
    --verbose

Add another Linux virtual machine to the existing deployment with a random alpha-numeric password:

    ./cloud-harness.py azure --action add_role \
    --service my-hosted-service \
    --deployment my-virtual-machine-deployment \
    --name my-second-ubuntu-virtual-machine \
    --label 'my virtual machine label' \
    --account my-storage-account \
    --blob b39f27a8b8c64d52b05eac6a62ebad85__Ubuntu-14_04-LTS-amd64-server-20140724-en-us-30GB \
    --os Linux \
    --network my-virtual-network-name \
    --subnet my-subnet-name \
    --size Medium \
    --verbose

Add CustomScript extension to the virtual machine:

    ./cloud-harness.py azure --action add_resource_extension \
    --service my-hosted-service \
    --deployment my-virtual-machine-deployment \
    --name my-second-ubuntu-virtual-machine \
    --extension CustomScript \
    --verbose

Add `ChefClient` extension to the virtual machine:

    ./cloud-harness.py azure --action add_resource_extension \
    --service my-hosted-service \
    --deployment my-virtual-machine-deployment \
    --name my-second-ubuntu-virtual-machine \
    --extension ChefClient \
    --verbose

Add data disk to virtual machine:

    ./cloud-harness.py azure --action add_data_disk \
    --service my-hosted-service \
    --deployment my-virtual-machine-deployment \
    --name my-second-ubuntu-virtual-machine \
    --account my-storage-account

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
