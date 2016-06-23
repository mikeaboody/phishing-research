import os
from guppy import hpy

class MemTracker(object):
    log_file_path = None
    heapy_instance = None

    @classmethod
    def initialize(cls, file_path):
        if MemTracker.log_file_path != None:
            raise RuntimeError("Already initialized.")
        MemTracker.log_file_path = file_path
        if os.path.exists(MemTracker.log_file_path):
            os.remove(MemTracker.log_file_path)
        with open(MemTracker.log_file_path, "a") as f:
            f.write("Beggining memory tracking.\n\n")


    @classmethod
    def logMemory(cls, section_name):
        if MemTracker.log_file_path == None:
            raise RuntimeError("Initialize before calling.")
        if MemTracker.heapy_instance == None:
            MemTracker.heapy_instance = hpy()
            MemTracker.heapy_instance.setrelheap()
        
        h = MemTracker.heapy_instance.heap()
        with open(MemTracker.log_file_path, "a") as f:
            f.write("Memory statistics for '" + section_name + "':\n")
            for i in range(len(h)):
                f.write(str(h[i]) + "\n")
            f.write("\n")
