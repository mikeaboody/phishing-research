from collections import defaultdict
from collections import Counter
from detector import Detector
import numpy as np
import re

APPLE_MSG_ID = re.compile('<[0-9A-Za-z]{8}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{12}@')

def has_apple_msgid(email):
    msgid = email['Message-ID']
    if msgid is None or not APPLE_MSG_ID.match(msgid):
        return False
    ua = email['User-Agent']
    if ua is not None and 'microsoft' in ua.lower():
        # Special case: if the mail client claims to be Microsoft,
        # then we don't override that.
        # There are known cases where Microsoft Outlook for Mac OS X
        # generates message ID's with the above format.
        return False
    return True

def is_apple_mailer(email):
    xm = email['X-Mailer']
    if xm is not None:
        xm = xm.lower()
        if 'apple' in xm or 'ipad' in xm or 'iphone' in xm:
            return True
    mv = email['Mime-Version']
    if mv is not None and 'apple' in mv.lower():
        return True
    ct = email['Content-Type']
    if ct is not None and 'apple' in ct.lower():
        return True
    return has_apple_msgid(email)

# MS_HDRS = ['X-MimeOLE', 'X-MS-Attach', 'X-MS-TNEF-Correlator', 'Thread-Index', 'acceptlanguage', 'Accept-Language', 'Content-Language']

def is_microsoft_mailer(email):
    if email['X-MimeOLE'] is not None:
        return True
    xm = email['X-Mailer']
    if xm is not None and 'microsoft' in xm.lower():
        return True
    ua = email['User-Agent']
    if ua is not None and 'microsoft' in ua.lower():
        return True
    return False

NUM_CATEGORIES = 3

def infer_mailer(email):
    if is_apple_mailer(email):
        return 'apple'
    elif is_microsoft_mailer(email):
        return 'microsoft'
    else:
        return 'other'

def logprob(k, n, ncategories):
    '''log-transform of probability that next outcome is c, given
       that we've observed n previous outcomes and k of them were c.'''
    # Apply add-one Laplace smoothing to compute log
    p = float(k+1) / float(n+ncategories)
    # log-transform
    return np.log((1.0/p) - 1.0)

class Profile(object):
    def __init__(self):
        self.emails = 0
        self.counts = Counter()

class MailClientDetector(Detector):
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
            m = infer_mailer(email)
            prof.counts[m] += 1

    def classify(self, phish):
        fv = [0.0, 0.0, 0.0]

        curr_sender = self.extract_from(phish)
        if not curr_sender or not curr_sender in self.sender_profile:
            return fv
        prof = self.sender_profile[curr_sender]

        m = infer_mailer(phish)
        if prof.emails > 0 and prof.counts[m] == 0:
            fv[0] = 1.0
            fv[1] = logprob(0, prof.emails, NUM_CATEGORIES)
        fv[2] = logprob(prof.counts[m], prof.emails, NUM_CATEGORIES)

        return fv

    def modify_phish(self, phish, msg):
        phish["Message-ID"] = msg["Message-ID"]
        phish["X-Mailer"] = msg["X-Mailer"]
        return phish
