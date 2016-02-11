from detector import Detector
import mailbox
import re

PATH_TO_INBOX_MBOX = "~/Documents/Fall15/research/Inbox.mbox"
PATH_TO_ARCHIVE_MBOX = "~/Documents/Fall15/research/Archived.mbox"

inbox = mailbox.mbox(PATH_TO_INBOX_MBOX)
#archive = mailbox.mbox(PATH_TO_ARCHIVE_MBOX)

#Has timezone abbrev
#att2 = re.compile("\(?[A-Z][A-Z][A-Z]\)?")
#Has timezone in offset
timezone_re = re.compile("([+-][0-9][0-9][0-9][0-9])")

sender_to_email_map = {}
sender_to_date_data = {}

num_emails = 0

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

def extract_name(msg):
    from_header = msg["From"]
    if not from_header or not isinstance(from_header, str):
        return None
    from_header = from_header.lower()
    r = re.compile(" *<.*> *")
    from_header = r.sub("", from_header)
    r = re.compile("^ +")
    from_header = r.sub("", from_header)
    return from_header

def process_mbox(mbox):
    for email in mbox:
        sender = extract_name(email)
        date = email["Date"]

        if sender is None:
            continue

        if sender not in sender_to_email_map:
            sender_to_email_map[sender] = [date]
        else:
            sender_to_email_map[sender].append(date)

class Date_Detector(Detector):
    def __init__(self, inbox):
        self.inbox = inbox

    def modify_phish(self, phish, msg):
        phish["Date"] = msg["Date"]
        return phish

    def classify(self, phish):
        sender = self.extract_from(phish)
        date = phish["Date"]

        if sender is None:
            return None

        if sender in sender_to_date_data:
            test_timezone = Timezone(date)
            return self.detect(sender_to_date_data[sender], test_timezone)

        return None

    def detect(self, date_data, test_timezone):
        for seen_timezone in date_data.timezones:
            if seen_timezone.same_timezone(test_timezone):
                return False
        return True


if __name__ == "__main__":
    process_mbox(inbox)
    #process_mbox(archive)

    num_detected = 0
    timezone_dist = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    timezone_count = {}

    for sender, emails in sender_to_email_map.items():
        date_data = DateData()
        for date in emails:
            num_emails += 1
            date_data.process_timezone(date)
            
            timezone_string = Timezone.convert_to_timezone_string(date)
            if timezone_string in timezone_count:
                timezone_count[timezone_string] += 1
            else:
                timezone_count[timezone_string] = 1

        sender_to_date_data[sender] = date_data
        curr_detected = date_data.num_detected()
        num_detected += curr_detected

        num_timezones = curr_detected + 1
        timezone_dist[num_timezones-1] += 1

    print ("Num Emails:", num_emails)
    print ("Num Detected:", num_detected)
    print ("False Detection:", num_detected/num_emails)
    print ("Distribution:", timezone_dist)
    print ("Timezone Counts:", timezone_count)

    d = Date_Detector(inbox)
    print("Detection Rate = " + str(d.run_trials()))
