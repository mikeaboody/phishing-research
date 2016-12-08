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
#Has a single-digit number that has no leading zero (e.g., 3, 7)
no_leading_zero = re.compile("(^|\s+)[1-9]\s+")

def date_to_template(date_string):
    """Returns a binary templates for a date string."""
    binary_template = 0
    for att in [att1, att2, att3, att4, att5, att6, att7]:
        if re.search(att, date_string):
            binary_template = binary_template | 1
        binary_template = binary_template << 1
    binary_template = binary_template >> 1
    return binary_template

def has_leading_zero(date_string):
    return re.search(leading_zero, date_string)

def has_no_leading_zero(date_string):
    return re.search(no_leading_zero, date_string)

def log_if_inconsistent(date_string):
    """Safeguard against unforeseen edge cases.
       Should hopefully be impossible for this to trigger."""
    if has_leading_zero(date_string) and has_no_leading_zero(date_string):
        logs.RateLimitedLog.log('Date: has both leading-zero and no-leading-zero', private=date)

class ZeroStatus(object):
    """For a single template, keep track of how many emails we've seen
       (from this sender) total, and how many of each zero type."""
    def __init__(self):
        self.num_with_leading_zero = 0
        self.num_with_no_leading_zero = 0
        self.total = 0

    def add_date(self, date):
        self.total += 1
        if has_leading_zero(date):
            self.num_with_leading_zero += 1
        if has_no_leading_zero(date):
            self.num_with_no_leading_zero += 1

    def plausibly_consistent(self, date):
        if self.num_with_leading_zero == 0 and self.num_with_no_leading_zero == 0:
            # So far we haven't seen any emails with either the
            # 'leading-zero' or the 'no-leading-zero' type, so we
            # have no clue what this sender does with single-digit numbers.
            # So we have to assume this date might be consistent with
            # past history.
            return True

        # If we reach this point, we have enough history that we
        # know whether this sender tends to format single-digit numbers
        # in the date string with a leading zero or with no leading zero.
        if has_leading_zero(date):
            return self.num_with_leading_zero > 0
        elif has_no_leading_zero(date):
            return self.num_with_no_leading_zero > 0
        else:
            return True

class Profile(object):
    """For a single sender, keep track of information about emails
       sent by that sender.  For each binary template, we keep some
       information about how many emails that sender sent that matched
       that template."""
    def __init__(self):
        self.templates = defaultdict(ZeroStatus)
        self.num_emails = 0

    def add_date(self, date):
        template = date_to_template(date)
        self.templates[template].add_date(date)
        self.num_emails += 1

class DateFormatDetector(Detector):
    """Attempts to detect spoofed emails based upon how the contents
       of the Date: header are formatted."""
    NUM_HEURISTICS = 3

    def __init__(self, inbox):
        self.sender_profile = defaultdict(Profile)
        self.inbox = inbox

    def modify_phish(self, phish, msg):
        phish["Date"] = msg["Date"]
        return phish

    def classify(self, phish):
        """Returns [s,n1,n2], where
           s = 1 if this email is suspicious (seems spoofed) or 0 if not,
           n1 = number of emails previously sent by this sender that have
                a Date: header formatted similarly,
           n2 = total number of emails previously sent by this sender
                (regardless of the format of their Date: header)."""
        sender = self.extract_from(phish)
        date = phish["Date"]

        if not date or not (sender in self.sender_profile):
            return [0, 0, 0]

        profile = self.sender_profile[sender]
        t = date_to_template(date)

        if not (t in profile.templates):
            return [1, 0, profile.num_emails]

        rv = [0, profile.templates[t].total, profile.num_emails]
        if not profile.templates[t].plausibly_consistent(date):
            rv[0] = 1
        # TODO: Add feature counting number of emails with similar zero
        return rv

    def create_sender_profile(self, num_samples):
        for i in range(num_samples):
            email = self.inbox[i]
            sender = self.extract_from(email)
            date = email["Date"]
    
            if sender and date:
                self.sender_profile[sender].add_date(date)
