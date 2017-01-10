from collections import defaultdict
import re
from detector import Detector

class XMailerDetector(Detector):
    def __init__(self, inbox):
        self.inbox = inbox
        self.sender_profile = defaultdict(set)
        self._already_created = False

    def update_sender_profile(self, email):
        curr_sender = self.extract_from(email)
        if curr_sender:
            curr_xmailer = self.getXMailer(email)
            self.sender_profile[curr_sender].add(curr_xmailer)

    def classify(self, phish):
        curr_sender = self.extract_from(phish)
        if not curr_sender:
            return
        curr_xmailer = self.getXMailer(phish)
        return curr_xmailer in self.sender_profile.get(curr_sender, set())

    def modify_phish(self, phish, msg):
        phish["X-Mailer"] = msg["X-Mailer"]
        return phish

    def extractVersion(self, xmailer):
        r = re.compile("\d+(\.\d+)+")
        return r.sub("", xmailer)

    def extractParentheticals(self, xmailer):
        pairings = [("\(", "\)"), ("\[", "\]"), ("\*", "\*"), ("<", ">"), ("\- ", ""), ("ver", ""), ("\(", ""), (" \d", "")]
        for left, right in pairings:
            exp = left + ".*" + right
            r = re.compile(exp)
            xmailer = r.sub("", xmailer)
        return xmailer

    def removeSpaces(self, xmailer):
        exp = " +$"
        r = re.compile(exp)
        xmailer = r.sub("", xmailer)
        return xmailer

    def getXMailer(self, msg):
        xmailer = msg["X-Mailer"]
        if not xmailer:
            return None
        # was: return self.removeSpaces(self.extractVersion(self.extractParentheticals(xmailer)))
        return self.extractVersion(self.extractParentheticals(xmailer)).strip().lower()


    def getSimilar(self, given_str, given_set):
        for s in given_set:
            # if s and given_str and Levenshtein.ratio(given_str, s) > 0.9:
            if (not s and not given_str) or (s and given_str and given_str.lower() == s.lower()):
                return s
        return False

