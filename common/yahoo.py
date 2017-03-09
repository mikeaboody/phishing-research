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

def parse_app(email):
    try:
        msgid = email['Message-ID']
        if msgid is None:
            return 'none'
        before_at = msgid.split('@')[0].lstrip('< ')
        app = before_at.split('.')[-1].lower()
        if app == 'qm' or app[0:5] == 'yahoo' or app[0:7] == 'android' or app[0:6] == 'bpmail':
            return app
    except Exception as e:
        print(e)
    return 'none'

def logprob(k, n):
    '''log of probability that next toss is heads, given we've
       observed n previous tosses and k of them came up heads.'''
    # Apply add-one Laplace smoothing, then take the log.
    return np.log(float(k+1) / float(n+2))

class Profile(object):
    def __init__(self):
        self.emails = 0
        self.yahoo_emails = 0
        self.client_apps = set()

    def add(self, email):
        self.emails += 1
        if sent_from_yahoo(email):
            self.yahoo_emails += 1
            self.client_apps.add(parse_app(email))

class YahooDetector(Detector):
    NUM_HEURISTICS = 6

    def __init__(self, inbox):
        self.inbox = inbox
        self.sender_profile = defaultdict(Profile)
        self._already_created = False

    def update_sender_profile(self, email):
        curr_sender = self.extract_from(email)
        if curr_sender:
            self.sender_profile[curr_sender].add(email)

    def classify(self, phish):
        fv = [0.0, 0.0, 0.0, 0.0, 0.0, 0.0]

        curr_sender = self.extract_from(phish)
        if not curr_sender or not curr_sender in self.sender_profile:
            return fv
        prof = self.sender_profile[curr_sender]

        is_from_yahoo = sent_from_yahoo(phish)
        if is_from_yahoo:
            if prof.emails > 0 and prof.yahoo_emails == 0:
                fv[0] = 1.0
            fv[1] = logprob(prof.yahoo_emails, prof.emails)
        else:
            if prof.emails > 0 and prof.yahoo_emails == prof.emails:
                fv[2] = 1.0
            fv[3] = logprob(prof.emails - prof.yahoo_emails, prof.emails)
        app = parse_app(phish)
        if is_from_yahoo and prof.yahoo_emails > 0 and not app in prof.client_apps:
            fv[4] = 1.0
            fv[5] = logprob(len(prof.client_apps), prof.emails)
        return fv

    def modify_phish(self, phish, msg):
        phish["Message-ID"] = msg["Message-ID"]
        phish["X-YMail-OSG"] = msg["X-YMail-OSG"]
        return phish

