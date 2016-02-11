import mailbox
import re
import sys

# Needed for Message ID Domain
import socket
from ipwhois import IPWhois

from detector import Detector

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

myEmail = "nexusapoorvacus19@gmail.com"
class messageIDDomain_Detector(Detector):
    GLOBAL_SET = {} # email domain : [MID domain 0, ...]
    domainCompanyPairing = {} # domain : company
    def __init__(self, inbox):
        self.inbox = inbox
        # self.sender_profile = self.create_sender_profile()

    def check_header(self, msg):
        mID = msg["Message-ID"]
        return mID is not None

    def modify_phish(self, phish, msg):
        phish["Message-ID"] = msg["Message-ID"]
        return phish

    def get_messageIDDomain(self, msg):
        mID = msg["Message-ID"]
        if mID == None:
            return None
        elif '@' not in mID:
            return mID
        return mID[mID.index('@') + 1 :-1]

    # if your message ID Domain is mx.google.com --> returns google
    def get_endMessageIDDomain(self, mID):
        if mID == None:
            return mID
        if '.' in mID:
            indexLastDot = len(mID) - mID[::-1].index(".") - 1
            rest = mID[:indexLastDot]
            if '.' in rest:
                indexNextDot = len(rest) - rest[::-1].index(".") - 1
                return mID[indexNextDot+1:]
        return mID
        
    def classify(self, phish):
        sender = self.getEntireEmail(phish["From"])
        mID = self.get_endMessageIDDomain(self.get_messageIDDomain(phish))

        if "List-Unsubscribe" in phish.keys() or myEmail in phish["From"] or mID == None:
                return False
        
        if sender in self.sender_profile.keys():
            if mID not in self.sender_profile[sender]:
                if self.getEmailDomain(sender) in self.GLOBAL_SET.keys():
                    if mID not in self.GLOBAL_SET[self.getEmailDomain(sender)]:
                        if self.noreplyFP(sender, phish["Message-ID"]) or self.orgGroups(sender, mID):
                            return False
                        else:
                            return self.checkGeneralMID(sender, mID)
        return False


    # returns true if needs to be flagged
    def checkGeneralMID(self, email, messageIDDomain):
        if type(messageIDDomain) == str and self.getEmailDomain(email) in messageIDDomain:
            return False
        return True

    # returns tdameritrade given client@notifications.tdameritrade.com
    def getEmailDomain(self, email):
        # import pdb; pdb.set_trace()
        indexAt = email.index("@")
        indexEnd = (len(email)-indexAt) - (email[indexAt:])[::-1].index(".") + indexAt - 1
        part = email[indexAt+1:indexEnd]
        if "." in part:
            i = part.index(".")
            return part[i+1:]
        return email[indexAt+1:indexEnd]

    # returns apoorva.dornadula@berkeley.edu given "Apoorva Dornadula <apoorva.dornadula@berkeley.edu>"
    def getEntireEmail(self, sender):
        if ("<" in sender and ">" in sender):
            leftBracket = sender.index("<")
            rightBracket = sender.index(">")
            return sender[leftBracket+1:rightBracket]
        return sender

    # returns True if FP and email will not be flagged
    def noreplyFP(self, sender, messageID):
        pattern = re.compile("no.*reply")
        if pattern.match(sender):
            # noreply case
            if "ismtpd" in messageID or ".mail" in messageID:
                return True
        return False

    # returns True if FP and email will not be flagged
    def orgGroups(self, sender, mID):
        # import pdb; pdb.set_trace()
        try:
            newmID = "www." + mID
            afterAT = "www." + sender[sender.index("@")+1:]

            if newmID in self.domainCompanyPairing.keys():
                res1 = self.domainCompanyPairing[newmID]
            else:
                ip1 = socket.gethostbyname(newmID)
                obj1 = IPWhois(ip1)
                res1 = obj1.lookup(get_referral=True)['nets'][0]['name']
                self.domainCompanyPairing[newmID] = res1

            if afterAT in self.domainCompanyPairing.keys():
                res2 = self.domainCompanyPairing[afterAT]
            else:
                ip2 = socket.gethostbyname(afterAT)
                obj2 = IPWhois(ip2)
                res2 = obj2.lookup(get_referral=True)['nets'][0]['name']
                self.domainCompanyPairing[afterAT] = res2
            
            if res1 == res2:
                return True
            return False
        except:
            return False

    def create_sender_profile(self, num_samples):
        emails_with_sender = 0
        no_messageIDDomain = 0
        new_format_found = 0
        sender_profile = {}
        for i in range(num_samples):
        # for msg in self.inbox:
            msg = self.inbox[i]
            if "List-Unsubscribe" in msg.keys() or myEmail in msg["From"]:
                continue
            sender = self.getEntireEmail(msg["From"])
            if sender:
                emails_with_sender += 1
                mID = self.get_endMessageIDDomain(self.get_messageIDDomain(msg))
                if mID == None:
                    no_messageIDDomain += 1
                    if sender not in sender_profile.keys():
                        sender_profile[sender] = set([])
                    sender_profile[sender].add("None")
                else:
                    wasntInSenderProfile = False
                    if sender in sender_profile.keys():
                        if mID not in sender_profile[sender]:
                            if self.toFlag(sender, mID):
                                wasntInSenderProfile = True
                            sender_profile[sender].add(mID)
                    else:
                        sender_profile[sender] = set([mID])
                    email_domain = self.getEmailDomain(sender)
                    if email_domain not in self.GLOBAL_SET.keys():
                        self.GLOBAL_SET[email_domain] = []

                    if mID not in self.GLOBAL_SET[email_domain]:
                        if (self.GLOBAL_SET[email_domain]):
                            if self.checkGeneralMID(sender, mID):
                                if wasntInSenderProfile:
                                    if not (self.noreplyFP(sender, msg["Message-ID"]) or self.orgGroups(sender, mID)):
                                        new_format_found += 1
                            self.GLOBAL_SET[email_domain].append(mID)
                        else:
                            self.GLOBAL_SET[email_domain] = [mID]

        self.emails_with_sender = emails_with_sender
        self.no_messageIDDomain = no_messageIDDomain
        self.new_format_found = new_format_found
        self.sender_profile = sender_profile
        return sender_profile

    def toFlag(self, sender, mID):
        return self.checkGeneralMID(sender, mID)




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
