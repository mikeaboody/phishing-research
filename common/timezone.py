from detector import Detector
from collections import Counter
from collections import defaultdict
import re

#Has timezone abbrev
#att2 = re.compile("\(?[A-Z][A-Z][A-Z]\)?")
#Has timezone in offset
timezone_re = re.compile("([+-][0-9][0-9][0-9][0-9])")

def extract_timezone(date_string):
    match = re.search(timezone_re, date_string)
    if match is not None:
        return match.group(0)
    return None

class Profile(object):
    def __init__(self):
        self.timezones = Counter()
        self.num_emails = 0

    def add_timezone(self, tz):
        self.timezones[tz] += 1
        self.num_emails += 1

class DateTimezoneDetector(Detector):
    NUM_HEURISTICS = 3

    def __init__(self, inbox):
        self.inbox = inbox
        self.sender_profile = defaultdict(Profile)

    def modify_phish(self, phish, msg):
        phish["Date"] = msg["Date"]
        return phish

    def classify(self, phish):
        sender = self.extract_from(phish)
        date = phish["Date"]

        if not date or not sender in self.sender_profile:
            return [0, 0, 0]

        tz = extract_timezone(date)
        profile = self.sender_profile[sender]
        if tz in profile.timezones:
            return [0, profile.timezones[tz], profile.num_emails]
        return [1, 0, profile.num_emails]

    def create_sender_profile(self, num_samples):
        for i in range(num_samples):
            email = self.inbox[i]
            sender = self.extract_from(email)
            date = email["Date"]

            if sender is None or date is None:
                continue

            self.sender_profile[sender].add_timezone(extract_timezone(date))
