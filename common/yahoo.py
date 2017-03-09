from collections import defaultdict
from detector import Detector
import numpy as np

def sent_from_yahoo(email):
    msgid = email['Message-ID']
    if msgid is not None and 'yahoo' in msgid.lower():
        return True
    if email['X-YMail-OSG'] is not None:
        return True
    if email['X-Yahoo-Newman-Id'] is not None:
        return True
    if email['X-Yahoo-Newman-Property'] is not None:
        return True
    if email['X-YMail-SMTP'] is not None:
        return True
    return False

# Message-ID may look like
# Message-ID: <1234567890.12345.YahooMailNeo@web123456.mail.ne1.yahoo.com>
# I tried parsing this to pull out the YahooMailNeo and use that, but it
# didn't help.

def logprob(k, n):
    '''log of probability that next toss is heads, given we've
       observed n previous tosses and k of them came up heads.'''
    # Apply add-one Laplace smoothing, then take the log.
    return np.log(float(k+1) / float(n+2))

class Profile(object):
    def __init__(self):
        self.emails = 0
        self.yahoo_emails = 0

class YahooDetector(Detector):
    NUM_HEURISTICS = 2

    def __init__(self, inbox):
        self.inbox = inbox
        self.sender_profile = defaultdict(Profile)
        self._already_created = False

    def update_sender_profile(self, email):
        curr_sender = self.extract_from(email)
        if curr_sender:
            prof = self.sender_profile[curr_sender]
            prof.emails += 1
            if sent_from_yahoo(email):
                prof.yahoo_emails += 1

    def classify(self, phish):
        fv = [0.0, 0.0]

        curr_sender = self.extract_from(phish)
        if not curr_sender or not curr_sender in self.sender_profile:
            return fv
        prof = self.sender_profile[curr_sender]

        is_from_yahoo = sent_from_yahoo(phish)
        if not is_from_yahoo:
            if prof.emails > 0 and prof.yahoo_emails == prof.emails:
                fv[0] = 1.0
            fv[1] = logprob(prof.emails - prof.yahoo_emails, prof.emails)
        return fv

    def modify_phish(self, phish, msg):
        phish["Message-ID"] = msg["Message-ID"]
        phish["X-YMail-OSG"] = msg["X-YMail-OSG"]
        return phish

