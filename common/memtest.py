import os
from guppy import hpy
import datetime as dt
import logging
import psutil

class MemTracker(object):
    logger = None
    heapy_instance = None
    proc = None

    @classmethod
    def initialize(cls, logger):
        if MemTracker.logger != None:
            raise RuntimeError("Already initialized.")
        MemTracker.logger = logger
        MemTracker.logger.info("Logger set. Relative heap set. Ready for memory tracking")
        MemTracker.heapy_instance = hpy()
        MemTracker.heapy_instance.setrelheap()
        MemTracker.proc = psutil.Process()


    @staticmethod
    def cur_mem_usage():
        return MemTracker.proc.memory_info().rss

    @classmethod
    def logMemory(cls, section_name):
        if MemTracker.logger == None:
            raise RuntimeError("Initialize before calling.")
        MemTracker.logger.info("Memory statistics for '" + section_name + "':")
        MemTracker.logger.info("Current total RSS: " + str(MemTracker.cur_mem_usage()))
        start = dt.datetime.now()
        h = MemTracker.heapy_instance.heap()
        MemTracker.logger.info(str(h))
        end = dt.datetime.now()
        delta = end - start
        MemTracker.logger.info("Profiling took " + str(delta.seconds) + " seconds.")

