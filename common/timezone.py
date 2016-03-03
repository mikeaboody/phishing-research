from detector import Detector
import mailbox
import re

#Has timezone abbrev
#att2 = re.compile("\(?[A-Z][A-Z][A-Z]\)?")
#Has timezone in offset
timezone_re = re.compile("([+-][0-9][0-9][0-9][0-9])")


class Timezone:
    def __init__(self, date_string):
        # Timezone
        self.timezone = Timezone.convert_to_timezone_string(date_string)

    def same_timezone(self, other):
        if (self.timezone != other.timezone):
            return False
        return True

    @staticmethod
    def convert_to_timezone_string(date_string):
        if not isinstance(date_string, str):
            return None
        match = re.search(timezone_re, date_string)
        if match is not None:
            return match.group(0)
        return None

class DateData:
    def __init__(self, dates=[]):
        self.dates = dates
        self.timezones = {}

    def process_timezone(self, date):
        self.dates.append(date)
        curr_timezone = Timezone(date)

        is_new_timezone = True
        for seen_timezone in self.timezones:
            if curr_timezone.same_timezone(seen_timezone):
                found_same = False
                self.timezones[seen_timezone] += 1
                break
        if is_new_timezone:
            self.timezones[curr_timezone] = 1

class DateTimezoneDetector(Detector):
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
            test_timezone = Timezone(date)
            return self.detect(self.sender_to_date_data[sender], test_timezone)

        return [0, 0, 0]

    def detect(self, date_data, test_timezone):
        for seen_timezone in date_data.timezones:
            if seen_timezone.same_timezone(test_timezone):
                return [0, date_data.timezones[seen_timezone], sum(date_data.timezones.itervalues())]
        return [1, 0, sum(date_data.timezones.itervalues())]

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

            num_detected = 0
            timezone_count = {}
    
        for sender, emails in self.sender_profile.items():
            date_data = DateData()
            for date in emails:
                date_data.process_timezone(date)
            self.sender_to_date_data[sender] = date_data

