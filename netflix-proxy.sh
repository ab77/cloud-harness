#!/bin/bash

# build netflix-proxy
rm -rf /opt/netflix-proxy && \
  git clone https://github.com/ab77/netflix-proxy /opt/netflix-proxy && \
  /opt/netflix-proxy/build.sh -c 127.0.0.1 -i 1 -d 1 -t 1
