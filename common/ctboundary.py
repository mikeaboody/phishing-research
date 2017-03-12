from collections import defaultdict
from collections import Counter
from detector import Detector
import numpy as np
import re

def has_quote(msg):
    ct = msg['Content-Type']
    return ct is not None and re.search('boundary="', ct) is not None

def has00(msg):
    ct = msg['Content-Type']
    return ct is not None and re.search('boundary="?__00', ct) is not None

def has00(msg):
    ct = msg['Content-Type']
    return ct is not None and re.search('boundary="?001a11', ct) is not None

def has_nextpart1(msg):
    ct = msg['Content-Type']
    return ct is not None and re.search('boundary="?----_=_NextPart', ct) is not None

def has_nextpart2(msg):
    ct = msg['Content-Type']
    return ct is not None and re.search('boundary="?----=_NextPart', ct) is not None

def has_part1(msg):
    ct = msg['Content-Type']
    return ct is not None and re.search('boundary="----=_Part_', ct) is not None

def has_part2(msg):
    ct = msg['Content-Type']
    return ct is not None and re.search('boundary="_----------=_MCPart_', ct) is not None

def has_part3(msg):
    ct = msg['Content-Type']
    return ct is not None and re.search('boundary=.*(mimepart|related_part|alternative_part|Multipart)', ct) is not None

def all_hex(msg):
    ct = msg['Content-Type']
    return ct is not None and re.search('boundary="?[a-f0-9]["; ]', ct) is not None

def has_4dash(msg):
    ct = msg['Content-Type']
    return ct is not None and re.search('boundary="?----[^-]', ct) is not None

def has_8_or_more_dash(msg):
    ct = msg['Content-Type']
    return ct is not None and re.search('boundary="?--------', ct) is not None

def has_b1(msg):
    ct = msg['Content-Type']
    return ct is not None and re.search('boundary="?b1_', ct) is not None

def has_B(msg):
    ct = msg['Content-Type']
    return ct is not None and re.search('boundary="?B_', ct) is not None

def has_equal(msg):
    ct = msg['Content-Type']
    return ct is not None and re.search('boundary="=', ct) is not None

def has_bnd(msg):
    ct = msg['Content-Type']
    return ct is not None and re.search('boundary="?.*(Boundary|MIMEBOundary|BOUNDARY)', ct) is not None

def ends_with_msgid1(msg):
    m = msg['Message-ID']
    ct = msg['Content-Type']
    if m is None or ct is None:
        return False
    id = re.sub('[^a-zA-Z0-9]', '', m)
    pat = 'boundary=".*_?' + id + '_?"'
    return re.search(pat, ct) is not None

def contains_msgid1(msg):
    m = msg['Message-ID']
    ct = msg['Content-Type']
    if m is None or ct is None:
        return False
    pat = 'boundary="(.*)"'
    match = re.search(pat, ct)
    if match is None:
        return False
    boundary = match.group(1)
    m = m.strip('<>')
    id = re.sub('[^a-zA-Z0-9]', '', m)
    bd = re.sub('[^a-zA-Z0-9]', '', boundary)
    return id in bd

def contains_msgid2(msg):
    m = msg['Message-ID']
    ct = msg['Content-Type']
    if m is None or ct is None:
        return False
    pat = 'boundary="(.*)"'
    match = re.search(pat, ct)
    if match is None:
        return False
    boundary = match.group(1)
    m = m.strip('<>')
    id = re.sub('[^a-zA-Z0-9]', '_', m)
    bd = re.sub('[^a-zA-Z0-9]', '_', boundary)
    return id in bd

matchers = [
    has_quote, has00, has00, has_nextpart1, has_nextpart2, has_part1, 
    has_part2, has_part3, all_hex, has_4dash, has_8_or_more_dash, has_b1, 
    has_B, has_equal, has_bnd, ends_with_msgid1, contains_msgid1, 
    contains_msgid2, 
]

def categorize(msg):
    category = 0
    for f in matchers:
        if f(msg):
            category = category | 1
        category = category << 1
    category = category >> 1
    return category
        
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

class CTBoundaryDetector(Detector):
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
            c = categorize(email)
            prof.counts[c] += 1

    def classify(self, phish):
        fv = [0.0, 0.0, 0.0]

        curr_sender = self.extract_from(phish)
        if not curr_sender or not curr_sender in self.sender_profile:
            return fv
        prof = self.sender_profile[curr_sender]

        c = categorize(phish)
        if prof.emails > 0 and prof.counts[c] == 0:
            fv[0] = 1.0
            fv[1] = logprob(0, prof.emails, len(prof.counts)+1)
        if prof.emails > 0:
            fv[2] = logprob(prof.counts[c], prof.emails, len(prof.counts)+1)
        return fv

    def modify_phish(self, phish, msg):
        phish["Content-Type"] = msg["Content-Type"]
        return phish
