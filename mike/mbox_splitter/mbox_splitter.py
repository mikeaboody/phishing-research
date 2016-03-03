from sys import argv
import mailbox
import os.path
import os
import shutil
import math

#Usage
#python3 mbox_splitter.py <file name> <# of parts> [max # of emails in a part]

path_name = argv[1]
file_name = os.path.basename(path_name)[:-5]
dir_name = file_name + "-split"
if os.path.isdir(dir_name):
    shutil.rmtree(dir_name)
os.makedirs(dir_name)
print("Loading input mbox...", end="",flush=True)
input_mbox = mailbox.mbox(path_name)
num_emails = len(input_mbox)
print("done.")
num_parts = int(argv[2])
if argv[3]:
    num_emails_per_part = int(argv[3])
else:
    num_emails_per_part = int(math.ceil(num_emails / num_parts))
num_emails_scanned = 0
for i in range(num_parts):
    start = num_emails_scanned
    end = start + num_emails_per_part - 1
    if end > num_emails - 1:
        end = num_emails - 1
    new_mbox_path = dir_name + "/" + file_name + str(start) + "-" + str(end) + ".mbox"
    print("Creating " + new_mbox_path + " for emails " + str(start) + "-" + str(end) + "...",end="", flush=True)
    new_mbox = mailbox.mbox(new_mbox_path, create=True)
    for j in range(start, end + 1):
        new_mbox.add(input_mbox[j])
        num_emails_scanned += 1
    new_mbox.flush()
    print("done.")

