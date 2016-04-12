#!/bin/sh

python broScripts/parse_pcap.py

python generate_features.py

python classify.py