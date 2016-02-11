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
        self.timezones = set()
        self.num_detections = 0

    def process_timezone(self, date):
        self.dates.append(date)
        curr_timezone = Timezone(date)

        found_same = False
        if len(self.timezones) == 0:
            self.timezones.add(curr_timezone)
            return

        for seen_timezone in self.timezones:
            if curr_timezone.same_timezone(seen_timezone):
                found_same = True
                break
        if not found_same:
            self.timezones.add(curr_timezone)
            self.num_detections += 1

    def num_detected(self):
        return self.num_detections

class DateTimezoneDetector(Detector):
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

        return False

    def detect(self, date_data, test_timezone):
        for seen_timezone in date_data.timezones:
            if seen_timezone.same_timezone(test_timezone):
                return False
        return True

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
            timezone_dist = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
            timezone_count = {}
    
        for sender, emails in self.sender_profile.items():
            date_data = DateData()
            for date in emails:
                date_data.process_timezone(date)
                
                timezone_string = Timezone.convert_to_timezone_string(date)
                if timezone_string in timezone_count:
                    timezone_count[timezone_string] += 1
                else:
                    timezone_count[timezone_string] = 1
    
            self.sender_to_date_data[sender] = date_data
            curr_detected = date_data.num_detected()
            num_detected += curr_detected
    
            num_timezones = curr_detected + 1
            timezone_dist[num_timezones-1] += 1

