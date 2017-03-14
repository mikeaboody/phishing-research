from detector import Detector
from collections import Counter
from collections import defaultdict
from email.utils import parsedate_tz, mktime_tz
from datetime import datetime
import re
import numpy as np

def parse_hour(msg):
    try:
        dt = msg['Date']
        tt = parsedate_tz(dt)
        timestamp = mktime_tz(tt)
        d = datetime.fromtimestamp(timestamp)
        return d.hour
    except:
        return None # couldn't parse the date

NUM_CATEGORIES = 25  # 24 hours of the day, plus 1 for None (parse error)
def logprob(k, n):
    '''log-transform of probability that next outcome is c, given
       that we've observed n previous outcomes and k of them were c.'''
    # Apply add-one Laplace smoothing to compute log
    p = float(k+1) / float(n+NUM_CATEGORIES)
    # log-transform
    return np.log((1.0/p) - 1.0)

class Profile(object):
    def __init__(self):
        # self.hours = Counter({0:1, 1:1, 2:1, 3:1, 4:1, 5:1, 6:1, 7:1, 8:2, 9:3, 10:5, 11:6, 12:6, 13:6, 14:7, 15:7, 16:7, 17:7, 18:6, 19:6, 20:5, 21:5, 22:5, 23:3, None:0})
        self.hours = Counter()
        self.num_emails = 0

    def add_hour(self, hour):
        self.hours[hour] += 1
        self.num_emails += 1

class TimeOfDayDetector(Detector):
    NUM_HEURISTICS = 1

    def __init__(self, inbox):
        self.inbox = inbox
        self.sender_profile = defaultdict(Profile)
        self._already_created = False

    def modify_phish(self, phish, msg):
        phish["Date"] = msg["Date"]
        return phish

    def classify(self, phish):
        sender = self.extract_from(phish)
        if sender is None or not sender in self.sender_profile:
            return 1.0

        hour = parse_hour(phish)
        profile = self.sender_profile[sender]

        return float(profile.hours[hour]+1) / float(profile.num_emails+NUM_CATEGORIES)

    def update_sender_profile(self, email):
        sender = self.extract_from(email)
        hour = parse_hour(email)
        if sender is not None:
            self.sender_profile[sender].add_hour(hour)
