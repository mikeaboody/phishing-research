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
	msg_tuples = []
	headers_added = set()
	for header in msg.keys():
		if header in headers_added:
			continue
		headers_added.add(header)
		key, value = header, msg[header]
		if msg.get_all(key) and len(msg.get_all(key)) > 1:
			for v in msg.get_all(key):
				msg_tuples.append((key, v))
		else:
			msg_tuples.append((key, value))
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
	with open('{}/emails.log'.format(sender_dir), 'a') as output_file:
		output_file.write(repr(msg_tuples) + "\n")
