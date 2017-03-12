from collections import defaultdict
from collections import Counter
from detector import Detector
import numpy as np
import re

hdrmap = {'from': 'f', 'subject': 's', 'to': 't', 'date': 'd',
          'message-id': 'm', 'mime-version': 'v', 'content-type': 'y',
          'x-mailer': 'x'}

def get_order(msg):
    l = [hdrmap[h.lower()] for h in msg.keys() if h.lower() in hdrmap]
    return ''.join(l)

def logprob(k, n, possible_outcomes):
    '''log-transform of probability that next outcome is c, given
       that we've observed n previous outcomes and k of them were c.'''
    # Apply add-one Laplace smoothing to compute log
    p = float(k+1) / float(n+possible_outcomes)
    # log-transform
    return np.log((1.0/p) - 1.0)

class Profile(object):
    def __init__(self):
        self.emails = 0
        self.counts = Counter()

class HdrOrderDetector(Detector):
    NUM_HEURISTICS = 3

    def __init__(self, inbox):
        self.inbox = inbox
        self.sender_profile = defaultdict(Profile)
        self._already_created = False

    def update_sender_profile(self, email):
        curr_sender = self.extract_from(email)
        if curr_sender:
            prof = self.sender_profile[curr_sender]
            prof.emails += 1
            order = get_order(email)
            prof.counts[order] += 1

    def classify(self, phish):
        fv = [0.0, 0.0, 0.0]

        curr_sender = self.extract_from(phish)
        if not curr_sender or not curr_sender in self.sender_profile:
            return fv
        prof = self.sender_profile[curr_sender]

        order = get_order(phish)
        if prof.emails > 0 and prof.counts[order] == 0:
            fv[0] = 1.0
            fv[1] = logprob(0, prof.emails, len(prof.counts)+1)
        if prof.emails > 0:
            fv[2] = logprob(prof.counts[order], prof.emails, len(prof.counts)+1)
        return fv

    def modify_phish(self, phish, msg):
        phish["Date"] = msg["Date"]
        return phish
