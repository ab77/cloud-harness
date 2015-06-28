## Cloud Harness
Python wrapper for cloud service provider APIs/SDKs.

### Supported Cloud Providers
Currently only one provider is supported:
* Azure Service Management using [Microsoft Azure Python SDK/API](https://github.com/Azure/azure-sdk-for-python)

### Installation and Configuration
* from a working Python environment, run `pip install azure`
* `/opt && git clone https://github.com/ab77/cloud-harness.git && cd ./cloud-harness`
* rename cloud-harness.sample.conf to cloud-harness.conf
* edit cloud-harness.conf, set `default_subscription_id` and `default_certificate_path`
* uncomment other configuration options as required
* run `python ./cloud-harness.py azure --help` to see command line options
