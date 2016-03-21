import glob
import os
import re
from subprocess import call

FILE_PATH = os.path.realpath(__file__)
DIR_NAME = os.path.dirname(FILE_PATH)

PCAP_DIRECTORY = DIR_NAME + '/input'
OUTPUT_DIRECTORY = DIR_NAME + '/output'

BRO_OUTPUT_FILE = DIR_NAME + '/smtp.log'

total_senders = 0
total_emails = 0

def clean_output():
    call(['rm', '-r', OUTPUT_DIRECTORY])

def summary_stats():
    print("Total unique senders: {}".format(total_senders))
    print("Total emails: {}".format(total_emails))

clean_output()

if not os.path.exists(OUTPUT_DIRECTORY):
    os.makedirs(OUTPUT_DIRECTORY)

for filename in glob.glob(PCAP_DIRECTORY + '/*.pcap'):
    call(['bro', '-r', filename, '-b', 'main.bro'])
    with open(BRO_OUTPUT_FILE) as f:
        for line in f:
            if line[0] != '#':
                headers = eval(line)
                sender = headers['FROM']
                sender = ''.join(sender.split()) # Remove all whitespace
                sender_email = re.findall(r'<(.*?)>', sender)
                if len(sender_email) > 0:
                    sender_email = sender_email[0]
                else:
                    continue
                first_subdir = sender_email[:3]
                second_subdir = sender_email[3:6]
                sender_dir = "{}/{}/{}/{}".format(OUTPUT_DIRECTORY,
                    first_subdir, second_subdir, sender_email)
                if not os.path.exists(sender_dir):
                    print('Creating Output Directory for {}'.format(sender_email))
                    total_senders += 1
                    os.makedirs(sender_dir)
                with open('{}/output.log'.format(sender_dir), 'a') as output_file:
                    total_emails += 1
                    output_file.write(line)

summary_stats()
