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
* run `python ./cloud-harness.py azure` for the default action `list_hosted_services`
* run `python ./cloud-harness.py azure --help` to see all available command line options
* to get get a list of required parameters for a particular action (e.g. `add_role`), run `python ./cloud-harness.py azure --action add_role`

#### Fiddler Proxy
To use `Fiddler2` to capture HTTPS traffic to the API
* export your Azure Management Certificate as base64 encoded  x.509 as ClientCertificate.cer
* place it into your `Fiddler2` directory (e.g. `C:\Users\<user>\Documents\Fiddler2`)
* set `proxy = True` in `cloud-harness.py` and re-launch `Fiddler2` [n1]

### Further Work
Lots, including:
* implement (at least) one additional cloud service provider
* add unittest framework
* implementat additional VM extensions
* move all defaults to config file

#### Notes
[n1] For more information, see [Using Fiddler to decipher Windows Azure PowerShell or REST API HTTPS traffic](http://blogs.msdn.com/b/avkashchauhan/archive/2013/01/30/using-fiddler-to-decipher-windows-azure-powershell-or-rest-api-https-traffic.aspx).
