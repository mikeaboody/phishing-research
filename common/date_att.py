from detector import Detector
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
#Nonstring
NONSTRING = -1

#Has leading zero
leading_zero = re.compile("(^|\s+)0[0-9]\s+")
#Does not have leading zero
no_leading_zero = re.compile("(^|\s+)[1-9]\s+")

class DateFormat:
    def __init__(self, date_string):
        self.date_string = date_string
        # Binary representation of a set of atts
        self.date_hash = self.att_binary(date_string)
        # 1 represents 0 seen, 2 represents no zero
        self.zeros_seen = set()
        # Add zero status to seen
        zero_stat = self.zero_status(date_string)
        self.add_zero_status(zero_stat)

    def same_hash(self, other):
        if (self.date_hash != other.date_hash):
            return False
        return True

    def add_zero_status(self, status):
        self.zeros_seen.add(status)

    @staticmethod
    def att_binary(date_string):
        if not isinstance(date_string, str):
            return NONSTRING
        att_binary = 0
        for att in [att1, att2, att3, att4, att5, att6, att7]:
            if (re.search(att, date_string) is not None):
                att_binary = att_binary | 1
            att_binary = att_binary << 1
        return att_binary >> 1

    @staticmethod
    def zero_status(date_string):
        if not isinstance(date_string, str):
            return 0
        if (re.search(leading_zero, date_string) is not None):
            return 1
        elif (re.search(no_leading_zero, date_string) is not None):
            return 2
        return 0

class DateData:
    def __init__(self, dates=[]):
        self.dates = dates
        self.seen_formats = {}

    def process_date(self, date):
        self.dates.append(date)
        curr_format = DateFormat(date)

        is_new_format = True
        curr_zero = list(curr_format.zeros_seen)[0]
        for seen_format in self.seen_formats.keys():
            if (curr_format.same_hash(seen_format)):
                is_new_format = False
                self.seen_formats[seen_format] += 1
                seen_format.add_zero_status(curr_zero)
                break
        if (is_new_format):
            self.seen_formats[curr_format] = 1

class DateFormatDetector(Detector):
    NUM_HEURISTICS = 3

    def __init__(self, inbox):
        self.sender_profile = {}
        self.sender_to_date_data = {}
        self.inbox = inbox

    def modify_phish(self, phish, msg):
        phish["Date"] = msg["Date"]
        return phish

    def classify(self, phish):
        sender = self.extract_from(phish)
        date = phish["Date"]

        if sender in self.sender_to_date_data:
            test_format = DateFormat(date)
            return self.detect(self.sender_to_date_data[sender], test_format)

        return [0, 0, 0]

    def detect(self, date_data, test_format):
        curr_zero = list(test_format.zeros_seen)[0]
        for seen_format in date_data.seen_formats:
            if (seen_format.same_hash(test_format) and ((curr_zero == 0 or curr_zero in seen_format.zeros_seen) or (len(seen_format.zeros_seen) == 1 and list(seen_format.zeros_seen)[0] == 0))):
                return [0, date_data.seen_formats[seen_format], sum(date_data.seen_formats.itervalues())]
        return [1, 0, sum(date_data.seen_formats.itervalues())]

    def create_sender_profile(self, num_samples):
        for i in range(num_samples):
            email = self.inbox[i]
            sender = self.extract_from(email)
            date = email["Date"]
    
            if sender is None:
                continue
    
            if sender not in self.sender_profile:
                self.sender_profile[sender] = [date]
            else:
                self.sender_profile[sender].append(date)

        for sender, emails in self.sender_profile.items():
            date_data = DateData()
            for date in emails:
                date_data.process_date(date)
            self.sender_to_date_data[sender] = date_data
    
