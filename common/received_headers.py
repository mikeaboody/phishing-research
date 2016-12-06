import re
import editdistance
import logging
from collections import defaultdict
from detector import Detector
from lookup import Lookup
import logs
from edbag import EDBag

"""Translate a hop in the mail path to its containing CIDR.
   A hop is a string from the Received: header identifying the
   server that the email passed through."""
def lookup_cidr_from_hop(hop):
    ip = Lookup.public_domain(hop)
    if not ip:
        ip = Lookup.public_IP(hop)
    return Lookup.getCIDR(ip) if ip else None

"""Given a Received: header, find the server it passed
   through and look up the containing CIDR netblock."""
def extract_cidr_from_rcvd_hdr(content):
    content = content.translate(None, '\n\r\t')
    for end_token in ["by", "via", "with", "id", "for", ";", "$"]:
        r = re.search('from +(.*) +' + end_token, content)
        if r:
            return lookup_cidr_from_hop(r.group(1).strip())
    return None

"""Given an email message, find the mail path.
   The mail path is the set of servers it passed through,
   except that we map each server's IP/domain name to the
   CIDR netblock it is contained in."""
def extract_mailpath_from_email(msg):
    rhdrs = msg.get_all("Received")
    return tuple(extract_cidr_from_rcvd_hdr(r) for r in rhdrs)

"""The sender profile for a single sender.
   Contains the set of mailpaths seen in emails from this
   sender, with a count indicating how many times each
   mailpath was seen."""
class Profile(EDBag):
    def add_mailpath(self, mailpath):
        self.add(mailpath)

    def distance_to_closest(self, mailpath):
        return self.closest_by_edit_distance(mailpath)[1]

class ReceivedHeadersDetector(Detector):
    NUM_HEURISTICS = 3

    def __init__(self, inbox):
        self.inbox = inbox
        self.sender_profile = defaultdict(Profile)

    def modify_phish(self, phish, msg):
        phish["Received"] = None
        if len(msg.get_all("Received")) != 0:
            phish["Received"] = []
            recHeaders = msg.get_all("Received")[:]
            for i in range(len(recHeaders)):
                phish["Received"].append(recHeaders[i])
        return phish

    def classify(self, phish):
        sender = self.extract_from(phish)
        mailpath = extract_mailpath_from_email(phish)

        if not sender in self.sender_profile:
            return [0, 0, 0]
        d = self.sender_profile[sender].distance_to_closest(mailpath)

        thresholds = [0, 1, 2]
        return [1 if d > t else 0 for t in thresholds]
        
    def create_sender_profile(self, num_samples):
        for i in range(num_samples):
            msg = self.inbox[i]
            sender = self.extract_from(msg)
            mailpath = extract_mailpath_from_email(msg)
            if sender:
                self.sender_profile[sender].add_mailpath(mailpath)
        self._log_large_profiles()

    def _log_large_profiles(self):
        maxpathlen = 0
        for profile in self.sender_profile.itervalues():
            maxpathlen = max(maxpathlen, len(profile))
        if maxpathlen >= 256:
            debug_logger = logging.getLogger('spear_phishing.debug')
            debug_logger.info('Large number of mailpaths ({}) for sender; {}'.format(maxpathlen, logs.context))
