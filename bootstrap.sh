#!/bin/bash

# install Git and update WAAgent
printf 'Scheduling WAAgent upgrade...\n'
printf 'sudo apt-get -y install git; \
sudo rm -rf ./WALinuxAgent; \
sudo git clone https://github.com/Azure/WALinuxAgent.git; \
sudo ./WALinuxAgent/get-agent.py; \
sudo service walinuxagent restart; \
sudo waagent -version' | at now

# unpack custom-data and execute contents
printf 'Processing custom data...\n'
