import mailbox
import re
import sys

# Needed for Message ID Domain
import socket
from ipwhois import IPWhois

from content_type import ContentTypeDetector
from date_att import DateFormatDetector
from detector import Detector
from order_of_headers import OrderOfHeaderDetector
from timezone import DateTimezoneDetector

class MessageIdDetectorOne(Detector):
    DELIMITERS = ['.', '-', '$', '/', '%']

    def __init__(self, regular_mbox):
        self.inbox = regular_mbox

    def most_common_delimiter(self, uid):
        highest_count = 0
        for delimiter in self.DELIMITERS:
            delim_count = uid.count(delimiter)
            if delim_count > highest_count:
                highest_count = delim_count
                freq_delim = delimiter
        if highest_count == 0:
            return None, 0
        else:
            return freq_delim, highest_count

    def partition_within_error(self, features, new_feature, fudge_factor=0):
        for old_feature in features:
            if old_feature[0] != new_feature[0] or old_feature[1] != new_feature[1]:
                continue
            old_partition_sizes = old_feature[2].split(' ')
            new_partition_sizes = new_feature[2].split(' ')
            old_sum = sum([int(x) for x in old_partition_sizes])
            new_sum = sum([int(x) for x in new_partition_sizes])
            if abs(old_sum - new_sum) <= fudge_factor:
                return True
        return False

    def partition_length(self, uid, delimiter, count):
        if count == 0:
            return str(len(uid))
        split_uid = uid.split(delimiter)
        return " ".join([str(len(split)) for split in split_uid])

    def create_sender_profile(self, num_samples):
        self.sender_profile = {}
        self.sender_count = {}
        for i in range(num_samples):
            msg = self.inbox[i]
            sender = self.extract_from(msg)
            message_id = msg["Message-ID"]
            if message_id == None:
                print ("No message ID found")
                continue
            split_msg_id = message_id.split('@')
            if len(split_msg_id) < 2:
                print("Message-ID misformatted: {}".format(message_id))
                continue
            domain = split_msg_id[1][:-1]
            uid = split_msg_id[0][1:]
            common_delimiter, delimiter_count = self.most_common_delimiter(uid)
            partition_sizes = self.partition_length(uid, common_delimiter, delimiter_count)
            features = (common_delimiter, delimiter_count, partition_sizes)
            if sender in self.sender_profile:
                is_valid = self.partition_within_error(self.sender_profile[sender], features, fudge_factor=2)
                if not is_valid:
                    self.sender_profile[sender].add(features)
                self.sender_count[sender] += 1
            else:
                self.sender_profile[sender] = set([features])
                self.sender_count[sender] = 1
        return self.sender_profile

    def classify(self, phish):
        sender = self.extract_from(phish)
        message_id = phish["Message-ID"]
        if message_id == None:
            print ("No message ID found")
            return False
        split_msg_id = message_id.split('@')
        if len(split_msg_id) < 2:
            print("Message-ID misformatted: {}".format(message_id))
            return False
        domain = split_msg_id[1][:-1]
        uid = split_msg_id[0][1:]
        common_delimiter, delimiter_count = self.most_common_delimiter(uid)
        partition_sizes = self.partition_length(uid, common_delimiter, delimiter_count)
        features = (common_delimiter, delimiter_count, partition_sizes)
        if sender in self.sender_profile:
            is_valid = self.partition_within_error(self.sender_profile[sender], features, fudge_factor=0)
            # if is_valid:
            #     return -self.sender_count[sender]
            # else:
            #     return self.sender_count[sender]
            return not is_valid
        else:
            return False

    def modify_phish(self, phish, msg):
        phish['Message-ID'] = msg['Message-ID']
        return phish

class MessageIdDetectorTwo(MessageIdDetectorOne):
    def create_sender_profile(self, num_samples):
        self.sender_profile = {}
        for i in range(num_samples):
            msg = self.inbox[i]
            sender = self.extract_from(msg)
            message_id = msg["Message-ID"]
            split_msg_id = message_id.split('@')
            if len(split_msg_id) < 2:
                print("Message-ID misformatted: {}".format(message_id))
                continue
            domain = split_msg_id[1][:-1]
            uid = split_msg_id[0][1:]
            common_delimiter, delimiter_count = self.most_common_delimiter(uid)
            partition_sizes = self.partition_length(uid, common_delimiter, delimiter_count)
            features = (common_delimiter, delimiter_count, partition_sizes)
            if sender in self.sender_profile:
                is_valid = self.partition_within_error(self.sender_profile[sender], features, fudge_factor=2)
                if not is_valid:
                    self.sender_profile[sender].add(features)
            else:
                self.sender_profile[sender] = set([features])
        return self.sender_profile

class MessageIdDetectorThree(MessageIdDetectorOne):
    """Non-binary version"""
    def classify(self, phish):
        sender = self.extract_from(phish)
        message_id = phish["Message-ID"]
        split_msg_id = message_id.split('@')
        if len(split_msg_id) < 2:
            print("Message-ID misformatted: {}".format(message_id))
            return False
        domain = split_msg_id[1][:-1]
        uid = split_msg_id[0][1:]
        common_delimiter, delimiter_count = self.most_common_delimiter(uid)
        partition_sizes = self.partition_length(uid, common_delimiter, delimiter_count)
        features = (common_delimiter, delimiter_count, partition_sizes)
        if sender in self.sender_profile:
            is_valid = self.partition_within_error(self.sender_profile[sender], features, fudge_factor=0)
            if is_valid:
                return -self.sender_count[sender]
            else:
                return self.sender_count[sender]
        else:
            return False

class ContentTransferEncodingDetector(Detector):
    def __init__(self, inbox):
        self.inbox = inbox

    def create_sender_profile(self, num_samples):
        self.sender_profile = {}
        for i in range(num_samples):
            msg = self.inbox[i]
            curr_sender = self.extract_from(msg)
            if curr_sender:
                # per sender
                curr_profile = self.sender_profile.get(curr_sender, set())
                curr_cte = self.getCTE(msg)
                similar_cte = self.getSimilar(curr_cte, curr_profile)
                if similar_cte == False:
                    curr_profile.add(curr_cte)
                self.sender_profile[curr_sender] = curr_profile
        count = 0

    def classify(self, phish):
        curr_sender = self.extract_from(phish)
        curr_cte = self.getCTE(phish)
        curr_profile = self.sender_profile.get(curr_sender, None)
        if not curr_profile:
            return False
        similar_cte = self.getSimilar(curr_cte, curr_profile)
        return similar_cte == False

    def modify_phish(self, phish, msg):
        phish["Content-Transfer-Encoding"] = msg["Content-Transfer-Encoding"]
        return phish

    def getCTE(self, msg):
        cte = msg["Content-Transfer-Encoding"]
        return cte

    def getSimilar(self, given_str, given_set):
        for s in given_set:
            # if s and given_str and Levenshtein.ratio(given_str, s) > 0.9:
            if (not s and not given_str) or (s and given_str and given_str.lower() == s.lower()):
                return s
        return False

class XMailerDetector(Detector):
    def __init__(self, inbox):
        self.inbox = inbox

    def create_sender_profile(self, num_samples):
        self.sender_profile = {}
        for i in range(num_samples):
            msg = self.inbox[i]
            curr_sender = self.extract_from(msg)
            if curr_sender:
                # per sender
                curr_profile = self.sender_profile.get(curr_sender, set())
                curr_xmailer = self.getXMailer(msg)
                similar_xmailer = self.getSimilar(curr_xmailer, curr_profile)
                if similar_xmailer == False:
                    curr_profile.add(curr_xmailer)
                self.sender_profile[curr_sender] = curr_profile
        count = 0

    def classify(self, phish):
        curr_sender = self.extract_from(phish)
        curr_xmailer = self.getXMailer(phish)
        curr_profile = self.sender_profile.get(curr_sender, None)
        if not curr_profile:
            return False
        similar_xmailer = self.getSimilar(curr_xmailer, curr_profile)
        return similar_xmailer == False

    def modify_phish(self, phish, msg):
        phish["X-Mailer"] = msg["X-Mailer"]
        return phish

    def extractVersion(self, xmailer):
        r = re.compile("\d+(\.\d+)+")
        return r.sub("", xmailer)

    def extractParentheticals(self, xmailer):
        pairings = [("\(", "\)"), ("\[", "\]"), ("\*", "\*"), ("<", ">"), ("\- ", ""), ("ver", ""), ("\(", ""), (" \d", "")]
        for left, right in pairings:
            exp = left + ".*" + right
            r = re.compile(exp)
            xmailer = r.sub("", xmailer)
        return xmailer

    def removeSpaces(self, xmailer):
        exp = " +$"
        r = re.compile(exp)
        xmailer = r.sub("", xmailer)
        return xmailer

    def getXMailer(self, msg):
        xmailer = msg["X-Mailer"]
        return None if not xmailer else self.removeSpaces(self.extractVersion(self.extractParentheticals(xmailer)))


    def getSimilar(self, given_str, given_set):
        for s in given_set:
            # if s and given_str and Levenshtein.ratio(given_str, s) > 0.9:
            if (not s and not given_str) or (s and given_str and given_str.lower() == s.lower()):
                return s
        return False

    def extract_name(self, msg):
        from_header = msg["From"]
        if not from_header:
            return None
        from_header = from_header.lower()
        r = re.compile(" *<.*> *")
        from_header = r.sub("", from_header)
        r = re.compile("^ +")
        from_header = r.sub("", from_header)
        return from_header
