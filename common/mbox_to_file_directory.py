import mailbox
from sys import argv
import os
import re
import shutil

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
	sender = ''.join(sender.split()) # Remove all whitespace
	sender_email = re.findall(r'<(.*?)>', sender)
	if len(sender_email) > 0:
		sender_email = sender_email[0]
	else:
		continue
	first_subdir = sender_email[:3]
	second_subdir = sender_email[3:6]
	sender_dir = "{}/{}/{}/{}".format(root_name,
					first_subdir, second_subdir, sender_email)
	if not os.path.exists(sender_dir):
		os.makedirs(sender_dir)
	with open('{}/output.log'.format(sender_dir), 'a') as output_file:
		output_file.write(repr(msg_dict) + "\n")
