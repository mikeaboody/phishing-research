import logging
import logging.handlers
import os

from common import phish_detector

# Usage:
# Normal operation: python spear_phishing_detector.py --all
# Debug mode: python spear_phishing_detector.py --debug_training

OUTPUT_DIRECTORY = "output"

def init_logger(name, filename, level=logging.DEBUG, to_stdout=True):
    """Creates a logger with the given name, logging to both the given filename
    and to STDOUT all messages above level."""

    l = logging.getLogger(name)
    l.setLevel(level)
    formatter = logging.Formatter(fmt='%(levelname)-8s %(asctime)-20s %(message)s',
                                  datefmt='%m/%d/%Y %H:%M:%S')
    fileHandler = logging.handlers.RotatingFileHandler(filename=filename,
                                                       mode='w',
                                                       maxBytes=10000000, # 10MB
                                                       backupCount=5)
    fileHandler.setFormatter(formatter)
    l.addHandler(fileHandler)

    if to_stdout:
        streamHandler = logging.StreamHandler()
        streamHandler.setFormatter(formatter)
        l.addHandler(streamHandler)

def main():
    if not os.path.exists(OUTPUT_DIRECTORY):
        os.makedirs(OUTPUT_DIRECTORY)

    init_logger('spear_phishing', OUTPUT_DIRECTORY + '/current.log', to_stdout=False)
    init_logger('spear_phishing.memory', OUTPUT_DIRECTORY + '/memory.log')
    init_logger('spear_phishing.progress', OUTPUT_DIRECTORY + '/progress.log')
    init_logger('spear_phishing.debug', OUTPUT_DIRECTORY + '/debug.log')

    progress_logger = logging.getLogger('spear_phishing.progress')
    progress_logger.info('Starting Spear Phishing Detector.')
    # TODO(matthew): Refactor parse_pcap to have a main method.
    from broScripts import parse_pcap
    os.chdir('common')
    phish_detector.main()
    os.chdir('..')
    progress_logger.info('Finished Spear Phishing Detector.')
    logging.shutdown()

if __name__ == '__main__':
    main()
