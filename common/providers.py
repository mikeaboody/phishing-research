from collections import defaultdict
from collections import Counter
from detector import Detector
import numpy as np

def sent_via_yahoo(email):
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

def sent_via_hotmail(email):
    msgid = email['Message-ID']
    if msgid is not None and 'phx.gbl' in msgid.lower():
        return True
    if email['X-OriginalArrivalTime'] is not None:
        return True
    if email['X-TMN'] is not None:
        return True
    return False

def sent_via_aol(email):
    msgid = email['Message-ID']
    if msgid is not None and 'aol.com' in msgid.lower():
        return True
    if email['x-aol-sid'] is not None:
        return True
    if email['x-aol-global-disposition'] is not None:
        return True
    if email['X-AOL-IP'] is not None:
        return True
    if email['X-AOL-SCOLL-URL_COUNT'] is not None:
        return True
    if email['X-AOL-SCOLL-SCORE'] is not None:
        return True
    if email['X-AOL-VSS-CODE'] is not None:
        return True
    if email['X-AOL-SENDER'] is not None:
        return True
    if email['X-AOL-ORIG-IP'] is not None:
        return True
    if email['X-MB-Message-Type'] is not None:
        return True
    if email['X-MB-Message-Source'] is not None:
        return True
    xm = email['X-Mailer']
    if xm is not None and 'aol' in xm.lower():
        return True
    ct = email['Content-Type']
    if ct is not None and 'aol.com' in ct.lower():
        return True
    return False

def sent_via_gmail(email):
    msgid = email['Message-ID']
    if msgid is not None and 'gmail.com' in msgid.lower():
        return True
    if email['X-Gm-Message-State'] is not None:
        return True
    if email['X-Google-DKIM-Signature'] is not None:
        return True
    return False

NUM_CATEGORIES = 5

def infer_provider(email):
    if sent_via_yahoo(email):
        return 'yahoo'
    elif sent_via_hotmail(email):
        return 'hotmail'
    elif sent_via_aol(email):
        return 'aol'
    elif sent_via_gmail(email):
        return 'gmail'
    else:
        return 'other'

def is_gmail_webmail(email):
    rhdrs = email.get_all('Received')
    if len(rhdrs) == 0:
        return False
    earliest_rcvd = rhdrs[-1]
    return 'with http' in earliest_rcvd.lower()

def is_aol_webmail(email):
    rhdrs = email.get_all('Received')
    if len(rhdrs) == 0:
        return False
    earliest_rcvd = rhdrs[-1].lower()
    if 'with http' in earliest_rcvd or 'webmailui' in earliest_rcvd:
        return True
    mbsrc = email['X-MB-Message-Source']
    if mbsrc is not None and 'webui' in mbsrc.lower():
        return True
    xm = email['X-Mailer']
    if xm is not None and 'webmail' in xm.lower():
        return True
    ct = email['Content-Type']
    if ct is not None and 'webmail' in ct.lower():
        return True
    return False

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
        self.aol_webmail = Counter()    # num emails sent via AOL webmail
        self.gmail_webmail = Counter()  # num emails sent via gmail webmail

class ProvidersDetector(Detector):
    NUM_HEURISTICS = 6

    def __init__(self, inbox):
        self.inbox = inbox
        self.sender_profile = defaultdict(Profile)
        self._already_created = False

    def update_sender_profile(self, email):
        curr_sender = self.extract_from(email)
        if curr_sender:
            prof = self.sender_profile[curr_sender]
            prof.emails += 1
            v = infer_provider(email)
            prof.counts[v] += 1
            if v == 'aol':
                prof.aol_webmail[is_aol_webmail(email)] += 1
            if v == 'gmail':
                prof.gmail_webmail[is_gmail_webmail(email)] += 1

    def classify(self, phish):
        fv = [0.0, 0.0, 0.0, 0.0, 0.0, 0.0]

        curr_sender = self.extract_from(phish)
        if not curr_sender or not curr_sender in self.sender_profile:
            return fv
        prof = self.sender_profile[curr_sender]

        v = infer_provider(phish)
        if prof.emails > 0 and prof.counts[v] == 0:
            fv[0] = 1.0
            fv[1] = logprob(0, prof.emails, NUM_CATEGORIES)
        fv[2] = logprob(prof.counts[v], prof.emails, NUM_CATEGORIES)

        if v == 'aol':
            w = is_aol_webmail(phish)
            k = prof.aol_webmail[w]
            n = prof.counts['aol']
            assert prof.aol_webmail[w] + prof.aol_webmail[not w] == n
        elif v == 'gmail':
            w = is_gmail_webmail(phish)
            k = prof.gmail_webmail[w]
            n = prof.counts['gmail']
            assert prof.gmail_webmail[w] + prof.gmail_webmail[not w] == n
        else:
            w, k, n = True, 0, 0

        if k == 0 and n > 0:
            fv[3] = 1.0
            fv[4] = logprob(0, n, 2)
        fv[5] = logprob(k, n, 2)

        return fv

    def modify_phish(self, phish, msg):
        phish["Message-ID"] = msg["Message-ID"]
        phish["X-YMail-OSG"] = msg["X-YMail-OSG"]
        return phish
