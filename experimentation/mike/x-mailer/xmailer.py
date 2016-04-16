from sys import argv
import mailbox
import pylab as pl
import numpy as np
import re
import random
import detector


class XMailerDetector(detector.Detector):

    def __init__(self, inbox):
        self.inbox = inbox
        print("Creating sender profile...")
        self.create_sender_profile()
        print("Done.")
        print("Running trials...")
        print(self.run_trials(1000))
        print("Done.")

    def create_sender_profile(self):
        self.sender_profile = {}
        for i in range(len(self.inbox)):
            msg = self.inbox[i]
            curr_sender = self.extract_from(msg)
            if curr_sender:
                # per sender
                curr_profile = self.sender_profile.get(curr_sender, set())
                curr_xmailer = getXMailer(msg)
                similar_xmailer = getSimilar(curr_xmailer, curr_profile)
                if similar_xmailer == False:
                    curr_profile.add(curr_xmailer)
                self.sender_profile[curr_sender] = curr_profile
        count = 0
    def classify(self, phish):
        curr_sender = self.extract_from(phish)
        curr_xmailer = getXMailer(phish)
        curr_profile = self.sender_profile.get(curr_sender, None)
        if not curr_profile:
            return False
        similar_xmailer = getSimilar(curr_xmailer, curr_profile)
        return similar_xmailer == False
    def modify_phish(self, phish, msg):
        phish["X-Mailer"] = msg["X-Mailer"]
        return phish

def extractVersion(xmailer):
    r = re.compile("\d+(\.\d+)+")
    return r.sub("", xmailer)


def extractParentheticals(xmailer):
    pairings = [("\(", "\)"), ("\[", "\]"), ("\*", "\*"), ("<", ">"), ("\- ", ""), ("ver", ""), ("\(", ""), (" \d", "")]
    for left, right in pairings:
        exp = left + ".*" + right
        r = re.compile(exp)
        xmailer = r.sub("", xmailer)
    return xmailer


def removeSpaces(xmailer):
    exp = " +$"
    r = re.compile(exp)
    xmailer = r.sub("", xmailer)
    return xmailer


def getXMailer(msg):
    xmailer = msg["X-Mailer"]
    return None if not xmailer else removeSpaces(extractVersion(extractParentheticals(xmailer)))


def getSimilar(given_str, given_set):
    for s in given_set:
        # if s and given_str and Levenshtein.ratio(given_str, s) > 0.9:
        if (not s and not given_str) or (s and given_str and given_str.lower() == s.lower()):
            return s
    return False


def extract_name(msg):
    from_header = msg["From"]
    if not from_header:
        return None
    from_header = from_header.lower()
    r = re.compile(" *<.*> *")
    from_header = r.sub("", from_header)
    r = re.compile("^ +")
    from_header = r.sub("", from_header)
    return from_header


file_name = "/Volumes/HP c310w/" + argv[1]
box = mailbox.mbox(file_name + ".mbox")
xmailer_detector = XMailerDetector(box)

#xmailer
#berkeley.edu: 14.9%
#gmail.com: 17.7%
