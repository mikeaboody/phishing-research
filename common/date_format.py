from detector import Detector
from collections import defaultdict
import re

#Has day of week
att1 = re.compile("Mon|Tue|Wed|Thu|Fri|Sat|Sun")
#Has timezone in paren
att2 = re.compile("\([A-Z][A-Z][A-Z]\)")
#Has timezone without paren
att3 = re.compile("\s+[A-Z][A-Z][A-Z]")
#Has timezone in offset
att4 = re.compile("[+-][0-9][0-9][0-9][0-9]")
#Has "Date:"
att5 = re.compile("Date:")
#Has one space
att6 = re.compile(",\s")
#Has three spaces
att7 = re.compile(",\s\s\s")

#Has a two-digit number with a leading zero (e.g., 02, 08)
leading_zero = re.compile("(^|\s+)0[0-9]\s+")
att8 = leading_zero
#Has a single-digit number that has no leading zero (e.g., 3, 7)
no_leading_zero = re.compile("(^|\s+)[1-9]\s+")
att9 = no_leading_zero

def date_to_templates(date_string):
    """Returns a set of binary templates for a date string --
       all possible templates that are consistent with the string."""

    binary_template = 0
    for att in [att1, att2, att3, att4, att5, att6, att7, att8, att9]:
        if re.search(att, date_string):
            binary_template = binary_template | 1
        binary_template = binary_template << 1
    binary_template = binary_template >> 1

    if binary_template & 3:
        # Has a number like 07 (so we know sender uses leading zeros)
        # or a number like 8 (so we know sender doesn't use leading zeros),
        # so there's only one template consistent with the string.
        return {binary_template}
    else:
        # All the numbers are like 27 or 13, so it's ambiguous
        # whether the sender uses leading zeros.
        # Both are possible, so return a set containing both possible
        # binary templates.
        return {binary_template|1, binary_template|2}

class Profile(object):
    def __init__(self):
        self.templates = defaultdict(int)
        self.num_emails = 0

    def add_date(self, date):
        templates = date_to_templates(date)
        for t in templates:
            self.templates[t] += 1
        self.num_emails += 1

class DateFormatDetector(Detector):
    NUM_HEURISTICS = 3

    def __init__(self, inbox):
        self.sender_profile = defaultdict(Profile)
        self.inbox = inbox

    def modify_phish(self, phish, msg):
        phish["Date"] = msg["Date"]
        return phish

    def classify(self, phish):
        sender = self.extract_from(phish)
        date = phish["Date"]

        if (sender in self.sender_profile) and date:
            profile = self.sender_profile[sender]
            email_templates = date_to_templates(date)
            for t in email_templates:
                if t in profile.templates:
                    return [0, profile.templates[t], profile.num_emails]
            return [1, 0, profile.num_emails]

        return [0, 0, 0]

    def create_sender_profile(self, num_samples):
        for i in range(num_samples):
            email = self.inbox[i]
            sender = self.extract_from(email)
            date = email["Date"]
    
            if sender and date:
                self.sender_profile[sender].add_date(date)
