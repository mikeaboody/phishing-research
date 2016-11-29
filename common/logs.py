import logging
import psutil
from memtest import MemTracker
import signal
import traceback
import threading
import sys

progress_logger = logging.getLogger('spear_phishing.progress')
debug_logger = logging.getLogger('spear_phishing.debug')
memory_logger = logging.getLogger('spear_phishing.memory')

# Set this to provide additional context that will be logged
context = {}

class RateLimitedMemTracker(object):
    all_tasks = {}

    def __init__(self, task=""):
        self.max_mem_logged = 100000000 # don't log until RSS reaches 100MB
        self.task = task

    def checkmem_rate_limited(self):
        cur = MemTracker.cur_mem_usage()
        if cur >= 2*self.max_mem_logged:
            self.max_mem_logged = cur
            MemTracker.logMemory(self.task + "; " + str(context))

    @classmethod
    def checkmem(cls, task):
        if not task in cls.all_tasks:
            cls.all_tasks[task] = RateLimitedMemTracker(task)
        cls.all_tasks[task].checkmem_rate_limited()

class RateLimitedLog(object):
    all_tasks = {}

    def __init__(self, task=""):
        self.times_called = 0
        self.last_logged  = 0
        self.task = task

    def log_rate_limited(self, private, public):
        self.times_called += 1
        if self.times_called < 2*self.last_logged:
            return
        progress_logger.info("{} (#{}): {}; {}".format(self.task, self.times_called, public, str(context)))
        if private != "":
            debug_logger.info("{} (#{}): {}; {}; {}".format(self.task, self.times_called, public, str(context), private))
        self.last_logged = self.times_called

    @classmethod
    def log(cls, task, private="", public=""):
        if not task in cls.all_tasks:
            cls.all_tasks[task] = RateLimitedLog(task)
        cls.all_tasks[task].log_rate_limited(private, public)

    @classmethod
    def flushall(cls):
        progress_logger.info('Summary of multiply-repeated log messages:')
        s = sorted(cls.all_tasks.values(), key=lambda l: l.times_called, reverse=True)
        for l in s:
            if l.times_called > 1:
                progress_logger("{: >5} instances of {}".format(l.times_called, l.task))




class Watchdog(object):
    duration = 600  # Initially, 10 minutes

    @classmethod
    def initialize(cls):
        signal.signal(signal.SIGALRM, cls.timer_expired)
        progress_logger.info('Started watchdog timer; {} seconds'.format(Watchdog.duration))
        cls.reset()

    @classmethod
    def reset(cls):
        signal.alarm(cls.duration)

    @staticmethod
    def log_all_stack_frames():
        # http://stackoverflow.com/a/2569696/781723
        id2name = dict([(th.ident, th.name) for th in threading.enumerate()])
        for threadId, stack in sys._current_frames().items():
            memory_logger.info(" # Thread: %s(%d)\n" % (id2name.get(threadId,""), threadId) + ''.join(traceback.format_stack(stack)))

    @staticmethod
    def timer_expired(sig, frame):
        progress_logger.info('Watchdog expired (more than {} seconds passed); {}'.format(Watchdog.duration, str(context)))
        memory_logger.info('Dumping all stack frames after watchdog expired:'.format(Watchdog.duration))
        Watchdog.log_all_stack_frames()
        MemTracker.logMemory('watchdog expired')
        Watchdog.duration *= 2
        progress_logger.info('Setting new watchdog timer, for {} seconds'.format(Watchdog.duration))
        Watchdog.reset()
