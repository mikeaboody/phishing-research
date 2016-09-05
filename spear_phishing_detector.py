import logging
import os

from common import phish_detector

# Usage: python spear_phishing_detector.py --all

def main():
	logging.basicConfig(format='%(levelname)-8s %(asctime)-20s %(message)s',
						datefmt='%m/%d/%Y %H:%M:%S',
						level=logging.DEBUG,
						filename='current.log')
	logging.info('Starting Spear Phishing Detector.')
	# TODO(matthew): Refactor parse_pcap to have a main method.
	from broScripts import parse_pcap
	os.chdir('common')
	phish_detector.main()
	os.chdir('..')
	logging.info('Finished Spear Phishing Detector.')

if __name__ == '__main__':
	main()