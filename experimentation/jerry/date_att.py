from detector import Detector
import mailbox
import re

PATH_TO_INBOX_MBOX = "~/Documents/Fall15/research/Inbox.mbox"
PATH_TO_ARCHIVE_MBOX = "~/Documents/Fall15/research/Archived.mbox"

inbox = mailbox.mbox(PATH_TO_INBOX_MBOX)
#archive = mailbox.mbox(PATH_TO_ARCHIVE_MBOX)

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

sender_to_email_map = {}
sender_to_date_data = {}

num_emails = 0

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
    def __init__(self):
        self.dates = []
        self.seen_formats = {}
        self.num_detections = 0

    def process_date(self, date):
        self.dates.append(date)
        curr_format = DateFormat(date)

        if (len(self.dates) == 1):
            self.seen_formats[curr_format] = 1
            return
            
        is_detection = True
        is_new_format = True
        curr_zero = list(curr_format.zeros_seen)[0]
        for seen_format in self.seen_formats.keys():
            if (curr_format.same_hash(seen_format)):
                if ((curr_zero == 0 or curr_zero in seen_format.zeros_seen) or (len(seen_format.zeros_seen) == 1 and list(seen_format.zeros_seen)[0] == 0)):
                    is_detection = False
                else:
                    is_detection = True
                is_new_format = False
                self.seen_formats[seen_format] += 1
                seen_format.add_zero_status(curr_zero)
                break
        if (is_detection):
            self.num_detections += 1
            if (is_new_format):
                self.seen_formats[curr_format] = 1

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
            test_format = DateFormat(date)
            return self.detect(sender_to_date_data[sender], test_format)

        return None

    def detect(self, date_data, test_format):
        curr_zero = list(test_format.zeros_seen)[0]
        for seen_format in date_data.seen_formats:
            if (seen_format.same_hash(test_format) and ((curr_zero == 0 or curr_zero in seen_format.zeros_seen) or (len(seen_format.zeros_seen) == 1 and list(seen_format.zeros_seen)[0] == 0))):
                return False
        return True

if __name__ == "__main__":
    process_mbox(inbox)
    #process_mbox(archive)

    num_detected = 0
    format_dist = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    format_count = {}

    for sender, emails in sender_to_email_map.items():
        date_data = DateData()
        for date in emails:
            num_emails += 1
            date_data.process_date(date)

            date_format = DateFormat.att_binary(date)
            if date_format in format_count:
                format_count[date_format] += 1
            else:
                format_count[date_format] = 1

        sender_to_date_data[sender] = date_data
        curr_detected = date_data.num_detected()
        num_detected += curr_detected

        format_dist[len(date_data.seen_formats)-1] += 1

    print ("Num Emails:", num_emails)
    print ("Num Detected:", num_detected)
    print ("False Detection:", num_detected/num_emails * 100, "%")
    print ("Distribution:", format_dist)
    print ("Count", format_count)

    d = Date_Detector(inbox)
    print("Detection Rate: ", d.run_trials(), "%")
