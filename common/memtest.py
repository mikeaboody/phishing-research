import os
from guppy import hpy
import datetime as dt

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
            now = dt.datetime.now()
            f.write("Relative heap set. Ready for memory tracking (TimeStamp: " + str(now) + ")\n\n")


    @classmethod
    def logMemory(cls, section_name):
        if MemTracker.log_file_path == None:
            raise RuntimeError("Initialize before calling.")
        if MemTracker.heapy_instance == None:
            MemTracker.heapy_instance = hpy()
            MemTracker.heapy_instance.setrelheap()
        
        with open(MemTracker.log_file_path, "a") as f:
            f.write("Memory statistics for '" + section_name + "':\n\n")
            start = dt.datetime.now()
            f.write("Starting TimeStamp: " + str(start))
            f.write("\n\n")
            h = MemTracker.heapy_instance.heap()
            f.write(str(h))
            f.write("\n\n")
            end = dt.datetime.now()
            f.write("Ending TimeStamp: " + str(end))
            delta = end - start
            f.write("\nProfiling took " + str(delta.seconds) + " seconds.")
            f.write("\n\n")
