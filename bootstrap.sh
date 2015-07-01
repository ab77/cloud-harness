#!/bin/bash

xpath_query='//oe:Environment/wa:ProvisioningSection/wa:LinuxProvisioningConfigurationSet/wa:CustomData'
xml_file='/var/lib/waagent/ovf-env.xml'
temp_script='/tmp/custom-data.tmp'
bootstrap_script='/tmp/custom-data.sh'

# unpack custom-data and execute contents
printf 'Processing custom data...\n'
sudo apt-get update; \
sudo apt-get -y install xmlstarlet
sudo xmlstarlet sel -t -v $xpath_query $xml_file | \
sudo base64 -d | sudo tee $temp_script && \
sudo cat $temp_script | sudo sed 's/^M$//' - | sudo sed $'s/\r$//' - | sudo tee $bootstrap_script && \
sudo chmod +x $bootstrap_script && \
sudo $bootstrap_script

# install Git and update WAAgent
printf 'Scheduling WAAgent upgrade...\n'
printf 'sudo apt-get -y install git; \
sudo rm -rf ./WALinuxAgent; \
sudo git clone https://github.com/Azure/WALinuxAgent.git; \
sudo ./WALinuxAgent/get-agent.py; \
sudo service walinuxagent restart; \
sudo waagent -version' | at now
