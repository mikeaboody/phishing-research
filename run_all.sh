#!/bin/sh

python broScripts/parse_pcap.py

pushd common
python generate_features.py
python classify.py
popd