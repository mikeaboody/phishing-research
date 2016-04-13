#!/bin/sh

python broScripts/parse_pcap.py

# cd common && python generate_features.py && python classify.py && cd ..
cd common && python phish_detector.py --all && cd ..