import mailbox
import re

PATH_TO_INBOX_MBOX = "~/Documents/Fall15/research/Inbox.mbox"
PATH_TO_ARCHIVE_MBOX = "~/Documents/Fall15/research/Archived.mbox"

inbox = mailbox.mbox(PATH_TO_INBOX_MBOX)
archive = mailbox.mbox(PATH_TO_ARCHIVE_MBOX)

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

#Has leading zero
leading_zero = re.compile("(^|\s+)0[0-9]\s+")
#Does not have leading zero
no_leading_zero = re.compile("(^|\s+)[1-9]\s+")

sender_to_email_map = {}
sender_to_date_data = {}

num_emails = 0

class DateFormat:
    def __init__(self, date_string):
        # Binary representation of a set of atts
        self.date_hash = self.att_binary(date_string)
        # 1 represents 0 seen, 2 represents no zero
        self.zeros_seen = []

        # Add zero seen if significant
        zero_stat = self.zero_status(date_string)
        if (zero_stat != None):
            self.zeros_seen.append(zero_stat)

    def same_hash(self, other):
        if (self.date_hash != other.date_hash):
            return False
        return True

    def add_zero_status(self, other):
        if (len(other.zeros_seen) != 0 and other.zeros_seen[0] not in self.zeros_seen):
            self.zeros_seen.append(other.zeros_seen[0])

    def att_binary(self, date_string):
        att_binary = 0
        for att in [att1, att2, att3, att4, att5, att6, att7]:
            if (re.search(att, date_string) is not None):
                att_binary = att_binary | 1
            att_binary = att_binary << 1
        return att_binary >> 1

    def zero_status(self, date_string):
        if (re.search(leading_zero, date_string) is not None):
            return 1
        elif (re.search(no_leading_zero, date_string) is not None):
            return 2
        return None

class DateData:
    def __init__(self, dates=[]):
        self.dates = dates
        self.seen_formats = {}

    def add_date(self, date):
        self.dates.append(date)

        curr_format = DateFormat(date)
        is_new_format = True
        for seen_format in self.seen_formats.keys():
            if (curr_format.same_hash(seen_format)):
                self.seen_formats[seen_format] += 1
                seen_format.add_zero_status(curr_format)
                is_new_format = False
        if (is_new_format):
            self.seen_formats[curr_format] = 0

    def num_detected(self):
        num_detected = -1
        for seen_format in self.seen_formats.keys():
            num_detected += 1
            if (len(seen_format.zeros_seen) == 2):
                num_detected += 1
        return num_detected

    def __str__(self):
        return "[]"

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

        if sender is None or not isinstance(date, str):
            continue

        if sender not in sender_to_email_map:
            sender_to_email_map[sender] = [date]
        else:
            sender_to_email_map[sender].append(date)

process_mbox(inbox)
process_mbox(archive)

num_detected = 0
format_dist = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

for sender, emails in sender_to_email_map.items():
    date_data = DateData()
    for date in emails:
        num_emails += 1
        date_data.add_date(date)
    sender_to_date_data[sender] = date_data
    curr_detected = date_data.num_detected()
    num_detected += curr_detected

    num_formats = curr_detected + 1
    format_dist[num_formats-1] += 1

print ("Num Emails:", num_emails)
print ("Num Detected:", num_detected)
print ("False Detection:", num_detected/num_emails)
print ("Distribution:", format_dist)
