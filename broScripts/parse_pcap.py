from email.utils import parseaddr
import glob
import os
import random
import re
from subprocess import call

import numpy as np

FILE_PATH = os.path.realpath(__file__)
DIR_NAME = os.path.dirname(FILE_PATH)

CURR_DIR = os.getcwd()

PCAP_DIRECTORY = DIR_NAME + '/input'
OUTPUT_DIRECTORY = 'broScripts/output'
BRO_LOG_DIRECTORY = DIR_NAME + '/bro_logs'

BRO_SCRIPT_PATH = DIR_NAME + '/main.bro'
BRO_OUTPUT_FILE = CURR_DIR + '/smtp.log'

SENDERS_FILE = OUTPUT_DIRECTORY + '/senders.log'

total_senders = 0
total_legit_emails = 0
total_phish_emails = 0
total_failed_parse = 0
total_pcaps = 0
total_only_hyphen = 0
num_pcaps_bro_failed = 0

eval_error_count = 0
mkdir_error_count = 0

def clean_all():
    try:
        call(['rm', '-r', OUTPUT_DIRECTORY])
        call(['rm', '-r', BRO_LOG_DIRECTORY])
    except Exception as e:
        pass

def summary_stats():
    print("")
    print("======== Summary Stats for Pcap Parsing Phase ========")
    print("Number of unique senders: {}".format(total_senders))
    print("Number of emails successfully parsed: {}".format(total_legit_emails))
    print("Number of pseudo-phish emails generated: {}".format(total_phish_emails))
    print("Number of emails failed to parse: {}".format(total_failed_parse))
    print("Number of pcaps parsed: {}".format(total_pcaps))
    print("Number of pcaps that Bro failed to parse: {}".format(num_pcaps_bro_failed))
    print("Number of emails represented only by a hyphen: {}".format(total_only_hyphen))
    print("")

def is_person_empty(field):
    return field == '' or field == '-' or field == '<>' or field == '(empty)' or field == 'undisclosed'

try:
    print("======== Starting Pcap Parsing Phase ========")
    clean_all()
    try:
        if not os.path.exists(OUTPUT_DIRECTORY):
            os.makedirs(OUTPUT_DIRECTORY)
        if not os.path.exists(BRO_LOG_DIRECTORY):
            os.makedirs(BRO_LOG_DIRECTORY)
    except Exception as e:
        print(e)

    # Generating legit emails
    senders_seen = open(SENDERS_FILE, 'a+')
    # senders_seen = []
    for filename in glob.glob(PCAP_DIRECTORY + '/*.pcap'):
        try:
            call(['bro', '-r', filename, '-b', BRO_SCRIPT_PATH])
        except Exception as e:
            print('Could not invoke bro on {}'.format(filename))
            num_pcaps_bro_failed += 1
            continue
        with open(BRO_OUTPUT_FILE, 'a+') as f:
            for line in f:
                if line == "-" or line == "-\n":
                    total_only_hyphen += 1
                    continue
                if line[0] == '[' and line[-2] == ']': # Check that this line represents an email
                    try:
                        headers = eval(line)
                    except SyntaxError as e:
                        if eval_error_count < 10:
                            eval_error_count += 1
                            print(e)
                            print(line)
                        total_failed_parse += 1
                        continue
                    sender = ''
                    for k, v in headers:
                        if k == 'FROM':
                            sender = v
                            senders_seen.write(v + '\n')
                            # senders_seen.append(v)
                            break
                    if not is_person_empty(sender):
                        name, address = parseaddr(sender)
                        name = name[:20].replace("/","")
                        address = address[:50].replace("/","")
                    else:
                        name, address = '', ''
                    if name:
                        first_subdir = name[:3].replace("/", "")
                        second_subdir = name[3:6].replace("/", "")
                        if second_subdir == '':
                            second_subdir = 'none'
                        sender_dir = "{}/{}/{}/{}/{}".format(OUTPUT_DIRECTORY,
                            first_subdir, second_subdir, name, address)
                    else:
                        name = 'noname'
                        sender_dir = "{}/{}/{}".format(OUTPUT_DIRECTORY, name, address)
                    if not os.path.exists(sender_dir):
                        print('Creating Output Directory for {}'.format(name))
                        try:
                            os.makedirs(sender_dir)
                            total_senders += 1
                        except Exception as e:
                            if mkdir_error_count < 10:
                                mkdir_error_count += 1
                                print(e)
                    with open('{}/legit_emails.log'.format(sender_dir), 'a') as output_file:
                        output_file.write(line)
                        total_legit_emails += 1
        last_index = filename.rfind('/')
        bro_filename = filename[last_index + 1:-4] + 'log'
        try:
            call(['mv', BRO_OUTPUT_FILE, '{}/{}'.format(BRO_LOG_DIRECTORY, bro_filename)])
        except Exception as e:
            print("Unable to move {}".format(bro_filename))
        total_pcaps += 1
    senders_seen.close()

    os.system('shuf {} > /dev/null'.format(SENDERS_FILE))

    # Generating phish emails
    senders_seen = open(SENDERS_FILE)
    # num_senders = len(senders_seen)
    for filename in glob.glob(BRO_LOG_DIRECTORY + '/*.log'):
        with open(filename, 'a+') as f:
            for line in f:
                if line[0] == '[' and line[-2] == ']':
                    try:
                        headers = eval(line)
                    except SyntaxError as e:
                        total_failed_parse += 1
                        continue
                    sender = ''
                    for k, v in headers:
                        if k == 'FROM':
                            # sender = v
                            # while sender == v:
                            #     new_index = np.random.randint(num_senders)
                            #     sender = senders_seen[new_index]
                            sender = senders_seen.readline().strip() # Remove newline character
                            from_index = headers.index((k, v))
                            headers.pop(from_index)
                            headers.insert(from_index, (k, sender))
                            break
                    if not is_person_empty(sender):
                        name, address = parseaddr(sender)
                        name = name[:20].replace("/","")
                        address = address[:50].replace("/","")
                    else:
                        name, address = '', ''
                    if name:
                        first_subdir = name[:3].replace("/","")
                        second_subdir = name[3:6].replace("/","")
                        if second_subdir == '':
                            second_subdir = 'none'
                        sender_dir = "{}/{}/{}/{}/{}".format(OUTPUT_DIRECTORY,
                            first_subdir, second_subdir, name, address)
                    else:
                        name = 'noname'
                        sender_dir = "{}/{}/{}".format(OUTPUT_DIRECTORY, name, address)
                    if not os.path.exists(sender_dir):
                        print("Missing sender directory for {}".format(sender_dir))
                        continue
                    with open('{}/phish_emails.log'.format(sender_dir), 'a') as output_file:
                        output_file.write(str(headers) + '\n')
                        total_phish_emails += 1
    if not total_phish_emails == total_legit_emails:
        print('Found {} phishing emails, {} legitimate emails'.format(total_phish_emails, total_legit_emails))
    senders_seen.close()
finally:
    summary_stats()
