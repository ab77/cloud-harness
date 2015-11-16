#!/bin/bash

xml_file='/var/lib/waagent/ovf-env.xml'
temp_script='/tmp/custom-data.tmp'
bootstrap_script='/tmp/custom-data.sh'

# unpack and execute custom-data script
printf 'Processing custom data...\n'
sudo env python -c "import xml.etree.ElementTree; from base64 import b64decode; f = open('$xml_file', 'r'); doc = xml.etree.ElementTree.fromstring(''.join(f.readlines())); print b64decode([el.text for el in doc.getiterator() if 'CustomData' in el.tag][0])" > $temp_script && \
sudo cat $temp_script | sudo sed 's/^M$//' - | sudo sed $'s/\r$//' - > $bootstrap_script && \
sudo chmod +x $bootstrap_script && \
printf 'Executing $bootstrap_script...\n'
sudo $bootstrap_script
