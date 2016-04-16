import mailbox
import re

PATH_TO_INBOX_MBOX = "~/Documents/Fall15/research/Inbox.mbox"
PATH_TO_ARCHIVE_MBOX = "~/Documents/Fall15/research/Archived.mbox"

inbox = mailbox.mbox(PATH_TO_INBOX_MBOX)
archive = mailbox.mbox(PATH_TO_ARCHIVE_MBOX)
#Wed, 18 Mar 2015 09:50:45 +0000 (UTC)
type1 = re.compile("[A-Z][a-z][a-z],\s[0-9][0-9]*\s[A-Z][a-z][a-z]\s[0-9][0-9][0-9][0-9]\s[0-9][0-9]:[0-9][0-9]:[0-9][0-9]\s[+-][0-9][0-9][0-9][0-9]\s\([A-Z][A-Z][A-Z]\)")
#Wed, 18 Mar 2015 09:50:45 +0000
type2 = re.compile("[A-Z][a-z][a-z],\s[0-9][0-9]*\s[A-Z][a-z][a-z]\s[0-9][0-9][0-9][0-9]\s[0-9][0-9]:[0-9][0-9]:[0-9][0-9]\s[+-][0-9][0-9][0-9][0-9]")
#Wed, 25 Feb 2015 09:04:44 GMT
type3 = re.compile("[A-Z][a-z][a-z],\s[0-9][0-9]*\s[A-Z][a-z][a-z]\s[0-9][0-9][0-9][0-9]\s[0-9][0-9]:[0-9][0-9]:[0-9][0-9]\s[A-Z][A-Z][A-Z]")
#21 Mar 2015 13:07:05 -0700
type4 = re.compile("[0-9][0-9]*\s[A-Z][a-z][a-z]\s[0-9][0-9][0-9][0-9]\s[0-9][0-9]:[0-9][0-9]:[0-9][0-9]\s[+-][0-9][0-9][0-9][0-9]")
#Wed,   18 Mar 2015 09:50:45 +0000
type5 = re.compile("[A-Z][a-z][a-z],\s\s\s[0-9][0-9]*\s[A-Z][a-z][a-z]\s[0-9][0-9][0-9][0-9]\s[0-9][0-9]:[0-9][0-9]:[0-9][0-9]\s[+-][0-9][0-9][0-9][0-9]\s\([A-Z][A-Z][A-Z]\)")
#Wed,   18 Mar 2015 09:50:45 +0000 (UTC)
type5 = re.compile("[A-Z][a-z][a-z],\s\s\s[0-9][0-9]*\s[A-Z][a-z][a-z]\s[0-9][0-9][0-9][0-9]\s[0-9][0-9]:[0-9][0-9]:[0-9][0-9]\s[+-][0-9][0-9][0-9][0-9]\s\([A-Z][A-Z][A-Z]\)\s\([A-Z][A-Z][A-Z]\)")
#Date: Thu, 08 Jul 2010 23:55:59 +0800
type6 = re.compile("Date:\s[A-Z][a-z][a-z],\s[0-9][0-9]*\s[A-Z][a-z][a-z]\s[0-9][0-9][0-9][0-9]\s[0-9][0-9]:[0-9][0-9]:[0-9][0-9]\s[+-][0-9][0-9][0-9][0-9]")

#For emails with dates 0x
#Wed, 08 Mar 2015 09:50:45 +0000 (UTC)
leading_zero = re.compile("0[1-9]\s[A-Z][a-z][a-z]")

#For emails with dates x
#Wed, 8 Mar 2015 09:50:45 +0000 (UTC)
no_leading_zero = re.compile("\s[1-9]\s[A-Z][a-z][a-z]")

sender_to_email_map = {}
sender_to_date_data = {}

num_emails = 0
num_detected = 0

class DateData:
    def __init__(self, dates=[]):
        self.dates = dates
        self.num_type1 = 0
        self.num_type2 = 0
        self.num_type3 = 0
        self.num_type4 = 0
        self.num_type5 = 0
        self.num_type6 = 0

        self.num_leading_zero = 0
        self.num_no_leading_zero = 0

        self.other_dates = []

    def add_date(self, date):
        if (re.match(type1, date) != None):
            self.num_type1 += 1
        elif (re.match(type2, date) != None):
            self.num_type2 += 1
        elif (re.match(type3, date) != None):
            self.num_type3 += 1
        elif (re.match(type4, date) != None):
            self.num_type4 += 1
        elif (re.match(type5, date) != None):
            self.num_type5 += 1
        elif (re.match(type6, date) != None):
            self.num_type6 += 1
        else:
            self.other_dates.append(date)
        if (re.search(leading_zero, date) != None):
            self.num_leading_zero += 1
        elif (re.search(no_leading_zero, date) != None):
            self.num_no_leading_zero += 1
        self.dates.append(date)

    def num_detected(self):
        num_formats = -1
        if (self.num_type1 > 0):
            num_formats += 1
        if (self.num_type2 > 0):
            num_formats += 1
        if (self.num_type3 > 0):
            num_formats += 1
        if (self.num_type4 > 0):
            num_formats += 1

        num_zero_formats = -1
        if (self.num_leading_zero > 0):
            num_zero_formats += 1
        if (self.num_no_leading_zero > 0):
            num_zero_formats += 1

        return max(num_formats, 0) + max(num_zero_formats, 0)

    def __str__(self):
        return "[" + str(self.num_type1) + ", " + str(self.num_type2) + ", " + str(self.num_type3) + ", " + str(self.num_type4) + ", " + str(self.num_leading_zero) + ", " + str(self.num_no_leading_zero) + "]"

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

for sender, emails in sender_to_email_map.items():
    date_data = DateData()
    for date in emails:
        num_emails += 1
        date_data.add_date(date)
    sender_to_date_data[sender] = date_data
    num_detected += date_data.num_detected()
    if len(date_data.other_dates) != 0:
        print (date_data.other_dates)

print (num_emails)
print (num_detected)
print (num_detected/num_emails)
