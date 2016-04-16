from sys import argv
import mailbox
import os.path
import os
import shutil
import math

#Usage
#python3 mbox_splitter.py split <input mbox> <# of partitions> [max emails in a partition]
#python3 mbox_splitter.py list <file name> <sizes of each group...>

def do_split(argv):
    path_name = argv[0]
    if not os.path.isfile(path_name):
        print("Error: file " + path_name + " not found.")
        return
    file_name = os.path.basename(path_name)[:-5]
    dir_name = file_name + "-split"
    if os.path.isdir(dir_name):
        shutil.rmtree(dir_name)
    os.makedirs(dir_name)
    print("Loading input mbox...", end="",flush=True)
    input_mbox = mailbox.mbox(path_name)
    num_emails = len(input_mbox)
    print("done.")
    num_parts = int(argv[1])
    if len(argv) == 3:
        num_emails_per_part = int(argv[2])
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
def do_list(argv):
    path_name = argv[0]
    if not os.path.isfile(path_name):
        print("Error: file " + path_name + " not found.")
        return
    file_name = os.path.basename(path_name)[:-5]
    dir_name = file_name + "-split"
    if os.path.isdir(dir_name):
        shutil.rmtree(dir_name)
    os.makedirs(dir_name)
    print("Loading input mbox...", end="",flush=True)
    input_mbox = mailbox.mbox(path_name)
    num_emails = len(input_mbox)
    print("done.")
    groups = [int(a) for a in argv[1:]]
    num_emails_scanned = 0
    for i in range(len(groups)):
        start = num_emails_scanned
        end = start + groups[i] - 1
        last_group = False
        if end >= num_emails - 1:
            end = num_emails - 1
            last_group = True
        new_mbox_path = dir_name + "/" + file_name + str(start) + "-" + str(end) + ".mbox"
        print("Creating " + new_mbox_path + " for emails " + str(start) + "-" + str(end) + "...",end="", flush=True)
        new_mbox = mailbox.mbox(new_mbox_path, create=True)
        for j in range(start, end + 1):
            new_mbox.add(input_mbox[j])
        new_mbox.flush()
        print("done.")
        if last_group:
            break
        num_emails_scanned += groups[i]
def do_usage(argv):
    print("Usage:")
    print("python3 mbox_splitter.py split <input mbox> <# of partitions> [max emails in a partition]")
    print("python3 mbox_splitter.py list <file name> <sizes of each group...>")
    print("")
    print("#############")
    print("####split####")
    print("#############")
    print("Splits the input mbox into the number of partitions specified with an optional argument for the maximum number of emails that can be in a partition. If the optional argument is left out, then the mbox is split evenly.")
    print("Example: python3 mbox_splitter.py split test.mbox 2 30")
    print("Puts emails 0-29 in the first mbox, and emails 30-59 in the second mbox.")
    print("")
    print("#############")
    print("####list#####")
    print("#############")
    print("Splits the input mbox into the each group with the sizes specified.")
    print("Example: python3 mbox_splitter.py list test.mbox 1 2 3 4")
    print("Puts email 0 into the first mbox, emails 1-2 in the second mbox, emails 3-5 in the third mbox, and emails 6-9 in the fourth mbox.")

if (len(argv) == 4 or len(argv) == 5) and argv[1] == "split":
    argv = argv[2:]
    do_split(argv)
elif len(argv) > 3 and argv[1] == "list":
    argv = argv[2:]
    do_list(argv)
else:
    do_usage(argv)

