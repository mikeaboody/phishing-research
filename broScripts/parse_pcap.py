from email.utils import parseaddr
import glob
import os
import random
import re
from subprocess import call

FILE_PATH = os.path.realpath(__file__)
DIR_NAME = os.path.dirname(FILE_PATH)

CURR_DIR = os.getcwd()

PCAP_DIRECTORY = DIR_NAME + '/input'
OUTPUT_DIRECTORY = DIR_NAME + '/output'
BRO_LOG_DIRECTORY = DIR_NAME + '/bro_logs'

BRO_SCRIPT_PATH = DIR_NAME + '/main.bro'
BRO_OUTPUT_FILE = CURR_DIR + '/smtp.log'

SENDERS_FILE = OUTPUT_DIRECTORY + '/senders.log'

total_senders = 0
total_legit_emails = 0
total_phish_emails = 0

def clean_all():
    call(['rm', '-r', OUTPUT_DIRECTORY])
    call(['rm', '-r', BRO_LOG_DIRECTORY])

def summary_stats():
    print("Total unique senders: {}".format(total_senders))
    print("Total legit emails: {}".format(total_legit_emails))
    print("Total phish emails generated: {}".format(total_phish_emails))

def is_person_empty(field):
    return field == '' or field == '-' or field == '<>' or field == '(empty)' or field == 'undisclosed'

clean_all()
if not os.path.exists(OUTPUT_DIRECTORY):
    os.makedirs(OUTPUT_DIRECTORY)
if not os.path.exists(BRO_LOG_DIRECTORY):
    os.makedirs(BRO_LOG_DIRECTORY)

# Generating legit emails
senders_seen = open(SENDERS_FILE, 'a+')
for filename in glob.glob(PCAP_DIRECTORY + '/*.pcap'):
    call(['bro', '-r', filename, '-b', BRO_SCRIPT_PATH])
    with open(BRO_OUTPUT_FILE, 'a+') as f:
        for line in f:
            if line[0] != '#':
                headers = eval(line)
                sender = ''
                for k, v in headers:
                    if k == 'FROM':
                        sender = v
                        senders_seen.write(v + '\n')
                        break
                if not is_person_empty(sender):
                    name, address = parseaddr(sender)
                else:
                    name, address = '', ''
                if name:
                    first_subdir = name[:3]
                    second_subdir = name[3:6]
                    sender_dir = "{}/{}/{}/{}/{}".format(OUTPUT_DIRECTORY,
                        first_subdir, second_subdir, name, address)
                else:
                    name = 'noname'
                    sender_dir = "{}/{}/{}".format(OUTPUT_DIRECTORY, name, address)
                if not os.path.exists(sender_dir):
                    print('Creating Output Directory for {}'.format(name))
                    total_senders += 1
                    os.makedirs(sender_dir)
                with open('{}/legit_emails.log'.format(sender_dir), 'a') as output_file:
                    total_legit_emails += 1
                    output_file.write(line)
    # call(['rm', BRO_OUTPUT_FILE])
    last_index = filename.rfind('/')
    bro_filename = filename[last_index + 1:-4] + 'log'
    call(['mv', BRO_OUTPUT_FILE, '{}/{}'.format(BRO_LOG_DIRECTORY, bro_filename)])
senders_seen.close()

os.system('shuf {} > /dev/null'.format(SENDERS_FILE))

# Generating phish emails
senders_seen = open(SENDERS_FILE)
for filename in glob.glob(BRO_LOG_DIRECTORY + '/*.log'):
    # call(['bro', '-r', filename, '-b', BRO_SCRIPT_PATH])
    with open(filename, 'a+') as f:
        for line in f:
            if line[0] != '#':
                headers = eval(line)
                sender = ''
                for k, v in headers:
                    if k == 'FROM':
                        sender = senders_seen.readline()[:-1] # Remove newline character
                        headers.remove((k, v))
                        headers.append((k, sender))
                        break
                if not is_person_empty(sender):
                    name, address = parseaddr(sender)
                else:
                    name, address = '', ''
                if name:
                    first_subdir = name[:3]
                    second_subdir = name[3:6]
                    sender_dir = "{}/{}/{}/{}/{}".format(OUTPUT_DIRECTORY,
                        first_subdir, second_subdir, name, address)
                else:
                    name = 'noname'
                    sender_dir = "{}/{}/{}".format(OUTPUT_DIRECTORY, name, address)
                assert os.path.exists(sender_dir), "Missing sender directory for {}".format(sender_dir)
                with open('{}/phish_emails.log'.format(sender_dir), 'a') as output_file:
                    total_phish_emails += 1
                    output_file.write(str(headers) + '\n')
assert total_phish_emails == total_legit_emails, 'Found {} phishing emails, {} legitimate emails'.format(total_phish_emails, total_legit_emails)
    # call(['rm', BRO_OUTPUT_FILE])
senders_seen.close()

summary_stats()
