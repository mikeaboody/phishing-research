import mailbox
from sys import argv
import os
import re
import shutil
from email.utils import parseaddr


def is_person_empty(field):
	return field == '' or field == '-' or field == '<>' or field == '(empty)' or field == 'undisclosed'

root_name = argv[2]
if os.path.exists(root_name):
	shutil.rmtree(root_name)
os.makedirs(root_name)
mbox_name = argv[1]
mbox = mailbox.mbox(mbox_name)
for msg in mbox:
	msg_dict = {}
	for header in msg.keys():
		msg_dict[header.upper()] = msg[header]
	sender = msg['From']
	if not is_person_empty(sender):
		name, address = parseaddr(sender)
	else:
		name, address = '', ''
	if name:
		first_subdir = name[:3]
		second_subdir = name[3:6]
		sender_dir = "{}/{}/{}/{}/{}".format(root_name, first_subdir, second_subdir, name, address)
	else:
		name = 'noname'
		sender_dir = "{}/{}/{}".format(root_name, name, address)

	if not os.path.exists(sender_dir):
		os.makedirs(sender_dir)
	with open('{}/output.log'.format(sender_dir), 'a') as output_file:
		output_file.write(repr(msg_dict) + "\n")
