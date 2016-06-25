import sys
import mailbox
import os

#Usage
#python3 mbox_cloner.py <mbox_file_path> <duplication_factor> <out_file_path>

def clone(mbox_file_path, num_times_size, out_file_path):
    if os.path.exists(out_file_path):
        os.remove(out_file_path)
    mbox_to_clone = mailbox.mbox(mbox_file_path)
    mbox_clone = mailbox.mbox(out_file_path, create=True)
    percentage = 0
    for i in range(len(mbox_to_clone)):
        if (i % (len(mbox_to_clone) // 10)) == 0:
            print(str(percentage) + "%")
            percentage += 10
        for _ in range(num_times_size):
            mbox_clone.add(mbox_to_clone[i])
    mbox_clone.flush()

if len(sys.argv) != 4:
    raise RuntimeError("Must pass in exactly 3 arguments.")

mbox_file_path = sys.argv[1]
num_times_size = int(sys.argv[2])
out_file_path = sys.argv[3]
clone(mbox_file_path, num_times_size, out_file_path)