import mailbox
from sys import argv
import os
import re
import shutil
from email.utils import parseaddr
from random import shuffle


def is_person_empty(field):
	return field == '' or field == '-' or field == '<>' or field == '(empty)' or field == 'undisclosed'

def getHeadersTupleList(msg, newFrom=None):
	msg_tuples = []
	headers_added = set()
	for header in msg.keys():
		if header in headers_added:
			continue
		if newFrom and header == "From":
			msg_tuples.append((header, newFrom))
			continue
		headers_added.add(header)
		key, value = header, msg[header]
		if msg.get_all(key) and len(msg.get_all(key)) > 1:
			for v in msg.get_all(key):
				msg_tuples.append((key, v))
		else:
			msg_tuples.append((key, value))
	return msg_tuples

def getSenderDir(sender):
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
	return sender_dir


root_name = argv[2]
if os.path.exists(root_name):
	shutil.rmtree(root_name)
os.makedirs(root_name)
mbox_name = argv[1]
mbox = mailbox.mbox(mbox_name)
senders = []
print("Generating legit_emails.log...")
for msg in mbox:
	msg_tuples = getHeadersTupleList(msg)
	sender = msg['From']
	senders.append(sender)
	
	sender_dir = getSenderDir(sender)

	if not os.path.exists(sender_dir):
		os.makedirs(sender_dir)
	with open('{}/legit_emails.log'.format(sender_dir), 'a') as output_file:
		output_file.write(repr(msg_tuples) + "\n")

shuffle(senders)

print("Generating phish_emails.log...")
for i,msg in enumerate(mbox):
	sender = senders[i]
	msg_tuples = getHeadersTupleList(msg, sender)
	
	sender_dir = getSenderDir(sender)

	if not os.path.exists(sender_dir):
		os.makedirs(sender_dir)
	with open('{}/phish_emails.log'.format(sender_dir), 'a') as output_file:
		output_file.write(repr(msg_tuples) + "\n")

