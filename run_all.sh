#!/bin/sh

python broScripts/parse_pcap.py

python common/generate_features.py

python common/classify.py