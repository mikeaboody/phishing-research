from email.utils import parseaddr
import glob
import logging
import os
import random
import re
from subprocess import call

import numpy as np

from common import logs
from common import parse_sender

FILE_PATH = os.path.realpath(__file__)
DIR_NAME = os.path.dirname(FILE_PATH)

CURR_DIR = os.getcwd()
MBOX_FILE_NAME = "mbox.log"
MBOX_FILE = "broScripts/mbox.log"
OUTPUT_DIRECTORY = 'broScripts/output'
BRO_LOG_DIRECTORY = DIR_NAME + '/bro_logs'

SENDERS_FILE = OUTPUT_DIRECTORY + '/senders.log'

total_senders = 0
total_legit_emails = 0
total_phish_emails = 0
total_failed_parse = 0
total_only_hyphen = 0
total_full_parse_error = 0
total_quote_paren_error = 0

eval_error_count = 0
mkdir_error_count = 0

progress_logger = logging.getLogger('spear_phishing.progress')
debug_logger = logging.getLogger('spear_phishing.debug')

def clean_all():
    try:
        call(['rm', '-r', OUTPUT_DIRECTORY])
        call(['rm', '-r', BRO_LOG_DIRECTORY])
    except Exception as e:
        pass

def summary_stats():
    progress_logger.info("======== Summary Stats for Pcap Parsing Phase ========")
    progress_logger.info("Number of unique senders: {}".format(total_senders))
    progress_logger.info("Number of emails successfully parsed: {}".format(total_legit_emails))
    progress_logger.info("Number of pseudo-phish emails generated: {}".format(total_phish_emails))
    progress_logger.info("Number of emails failed to parse: {}".format(total_failed_parse))
    progress_logger.info("Number of emails represented only by a hyphen: {}".format(total_only_hyphen))
    progress_logger.info("Number of emails that could not be parsed fully: {}".format(total_full_parse_error))
    progress_logger.info("Number of emails with a quote+parenthesis in the header or header value: {}".format(total_quote_paren_error))
    progress_logger.info("======== Finished Pcap Parsing Phase ========")

def is_person_empty(field):
    return field == '' or field == '-' or field == '<>' or field == '(empty)' or field == 'undisclosed'

def parseLine(line):
    global total_full_parse_error
    global total_quote_paren_error
    fullLine = line
    lstOfTups = []
    while True:
        if "('" not in line or "')" not in line or "','" not in line:
            if line and line != '\n':
                total_full_parse_error += 1
                raise ValueError("This email could not be fully parsed: " + fullLine)
                return []
            return lstOfTups
        startParen = line.index("('")
        endParen = line.index("')")+1
        comma = line.index("','") + 1

        if endParen < comma:
            total_quote_paren_error += 1
            raise ValueError("This email's header or value has a quote+parenthesis: " + fullLine)
            return []
        header = line[startParen+2:comma-1]
        value = line[comma+2:endParen-1]

        # remove duplicate escaping from Python
        # matches the way eval deals with quotes
        header = header.replace('\\\\\"', '\\\"')
        value = value.replace('\\\\\"', '\\\"')

        header = header.replace("\\\\\'", "\\\'")
        value = value.replace("\\\\\'", "\\\'")

        lstOfTups.append((header, value))

        line = line[endParen+2:]
try:
    progress_logger.info("======== Starting Pcap Parsing Phase ========")
    clean_all()
    try:
        if not os.path.exists(OUTPUT_DIRECTORY):
            os.makedirs(OUTPUT_DIRECTORY)
        if not os.path.exists(BRO_LOG_DIRECTORY):
            os.makedirs(BRO_LOG_DIRECTORY)
    except Exception as e:
        debug_logger.exception(e)

    # Generating legit emails
    senders_seen = open(SENDERS_FILE, 'a+')
    dir_num = 0
    with open(MBOX_FILE, 'r+') as f:
        for line in f:
            if line == "-" or line == "-\n":
                total_only_hyphen += 1
                continue
            if line[0] == '[' and line[-2] == ']': # Check that this line represents an email
                try:
                    headers = parseLine(line)
                except (SyntaxError, ValueError) as e:
                    if eval_error_count < 10:
                        eval_error_count += 1
                        debug_logger.exception(e)
                    total_failed_parse += 1
                    continue
                sender = ''
                for k, v in headers:
                    if k == 'FROM':
                        sender = v
                        senders_seen.write(v + '\n')
                        break
                sender_dir = parse_sender.dir_for_sender(sender, OUTPUT_DIRECTORY)
                if not os.path.exists(sender_dir):
                    dir_num += 1
                    logs.RateLimitedLog.log('Creating directory', public=str(dir_num))
                    try:
                        os.makedirs(sender_dir)
                        total_senders += 1
                    except Exception as e:
                        if mkdir_error_count < 10:
                            mkdir_error_count += 1
                            debug_logger.exception(e)
                with open('{}/legit_emails.log'.format(sender_dir), 'a') as output_file:
                    output_file.write(repr(headers) + '\n')
                    total_legit_emails += 1
    try:
        call(['cp', MBOX_FILE, '{}/{}'.format(BRO_LOG_DIRECTORY, MBOX_FILE_NAME)])
    except Exception as e:
        debug_logger.exception("Unable to move {}".format(bro_filename))
    progress_logger.info('Done.  Created #{} directories.'.format(dir_num))
    senders_seen.close()

    shuffle_command = "shuf {} --output={}".format(SENDERS_FILE, SENDERS_FILE)
    progress_logger.info("Executing: {}".format(shuffle_command))
    os.system(shuffle_command)

    # Generating phish emails
    senders_seen = open(SENDERS_FILE)
    for filename in sorted(glob.glob(BRO_LOG_DIRECTORY + '/*.log')):
        with open(filename, 'r+') as f:
            for line in f:
                if line[0] == '[' and line[-2] == ']':
                    try:
                        headers = parseLine(line)
                    except (SyntaxError, ValueError) as e:
                        continue
                    sender = ''
                    for k, v in headers:
                        if k == 'FROM':
                            sender = senders_seen.readline().strip() # Remove newline character
                            from_index = headers.index((k, v))
                            headers.pop(from_index)
                            headers.insert(from_index, (k, sender))
                            break
                    sender_dir = parse_sender.dir_for_sender(sender, OUTPUT_DIRECTORY)
                    if not os.path.exists(sender_dir):
                        debug_logger.warning("Missing sender directory for {}".format(sender_dir))
                        continue
                    with open('{}/phish_emails.log'.format(sender_dir), 'a') as output_file:
                        output_file.write(repr(headers) + '\n')
                        total_phish_emails += 1
    if not total_phish_emails == total_legit_emails:
        progress_logger.warning('Found {} phishing emails, {} legitimate emails'.format(total_phish_emails, total_legit_emails))
    senders_seen.close()
finally:
    summary_stats()
