from collections import defaultdict
from collections import Counter
from detector import Detector
from lookup import Lookup
from lookup import getBinaryRep
from netaddr import IPNetwork, IPAddress, ZEROFILL
import numpy as np
import re

IS_IP_ADDR = re.compile(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$')

def get_ip_from_hdr(msg):
    ip = msg['X-Originating-IP']
    if ip is not None:
        ip = ip.strip('[] ')
        if IS_IP_ADDR.match(ip):
            return ip
    ip = msg['X-AOL-IP']
    if ip is not None:
        ip = ip.strip('[] ')
        if IS_IP_ADDR.match(ip):
            return ip
    ip = msg['X-SOURCE-IP']
    if ip is not None:
        ip = ip.strip('[] ')
        if IS_IP_ADDR.match(ip):
            return ip
    return None

AFTER_FROM = re.compile(r'from\s+(.*)', re.DOTALL)
BEFORE_REST = re.compile(r'(;|\sby\s|\swith\s|\svia\s|\sid\s|\sfor\s).*',
                         re.DOTALL)
IP_ADDR = re.compile(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')

def get_ip_from_rcvd(msg):
    rcvd_hdrs = msg.get_all('Received')
    if rcvd_hdrs is None or len(rcvd_hdrs) == 0:
        return None
    first_rcvd_hdr = rcvd_hdrs[-1]   # chronologically first received header
    m = AFTER_FROM.search(first_rcvd_hdr)
    if m is None:
        return None
    all = m.group(1).strip()
    frm = BEFORE_REST.sub('', all)
    m = IP_ADDR.search(frm)
    if m is None:
        return None
    return m.group().strip()

def get_ip(msg):
    return get_ip_from_hdr(msg) or get_ip_from_rcvd(msg)

privatenets = {
  IPNetwork("10.0.0.0/8"): getBinaryRep("10.0.0.0", 8),
  IPNetwork("172.16.0.0/12"): getBinaryRep("172.16.0.0", 12),
  IPNetwork("192.168.0.0/16"): getBinaryRep("192.168.0.0", 16),
}

def ip_to_private_cidr(ip):
    addr = IPAddress(ip, flags=ZEROFILL)
    for net, result in privatenets.items():
        if addr in net:
            return result
    return None

def ip_to_cidr(ip):
    return ip_to_private_cidr(ip) or Lookup.getCIDR(ip)

def get_cidr(msg):
    ip = get_ip(msg)
    if ip:
        return ip_to_cidr(ip)
    else:
        return None

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

class SenderIPDetector(Detector):
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
            netblock = get_cidr(email)
            prof.counts[netblock] += 1

    def classify(self, phish):
        fv = [0.0, 0.0, 0.0]

        curr_sender = self.extract_from(phish)
        if not curr_sender or not curr_sender in self.sender_profile:
            return fv
        prof = self.sender_profile[curr_sender]

        netblock = get_cidr(phish)
        if prof.emails > 0 and prof.counts[netblock] == 0:
            fv[0] = 1.0
            fv[1] = logprob(0, prof.emails, len(prof.counts)+1)
        if prof.emails > 0:
            fv[2] = logprob(prof.counts[netblock], prof.emails, len(prof.counts)+1)
        return fv

    def modify_phish(self, phish, msg):
        phish["Received"] = msg["Received"]
        return phish
