import mailbox
import re
import sys

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

scheme_number = 4
class messageIDDomain_Detector(Detector):
    GLOBAL_SET = {} # email domain : [MID domain 0, ...]
    def __init__(self, inbox):
        self.inbox = inbox

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
            else:
                return mID
        else:
            return mID

    def classify(self, phish):
        sender = phish["From"]
        mID = self.get_endMessageIDDomain(self.get_messageIDDomain(phish))

        if "List-Unsubscribe" in phish.keys():
                return False

        # Universal
        if (scheme_number >= 1 and scheme_number <= 3):
            if sender in self.sender_profile.keys():
                if mID not in self.sender_profile[sender]:
                    return self.toFlag(sender, mID)
            else:
                raise Exception("Sender was not found in sender_profile.")
        elif (scheme_number == 4):
            if self.getEmailDomain(sender) in self.GLOBAL_SET.keys():
                if mID not in self.GLOBAL_SET[self.getEmailDomain(sender)]:
                    return self.checkGeneralMID(sender, mID)
        else:
            raise Exception("The scheme_number is not between 1 and 4 inclusive.")
        return False

    # returns true if needs to be flagged
    def checkObviousMID(self, email, messageIDDomain):
        if "yahoo" in email:
            if type(messageIDDomain) == str and "yahoo" not in messageIDDomain:
                return True
            else:
                return False
        elif type(messageIDDomain) == str and "gmail" in email:
            if "gmail" in messageIDDomain or "google" in messageIDDomain or "android" in messageIDDomain:
                return False
            else:
                return True
        elif type(messageIDDomain) == str and "github" in email:
            if "github" not in messageIDDomain:
                return True
            else:
                return False
        elif type(messageIDDomain) == str and "wellsfargo" in email:
            if "wellsfargo" not in messageIDDomain:
                return True
            else:
                return False
        elif "spotify" in email or "glassdoor" in email:
            if type(messageIDDomain) == str and "sendgrid" in messageIDDomain:
                return False

        return True

    # returns true if needs to be flagged --> Intelligent Scheme 2
    def checkGeneralMID(self, email, messageIDDomain):
        if type(messageIDDomain) == str and self.getEmailDomain(email) in messageIDDomain:
            return False
        return True

    def getEmailDomain(self, email):
        indexAt = email.index("@")
        indexEnd = (len(email)-indexAt) - (email[indexAt:])[::-1].index(".") + indexAt - 1
        part = email[indexAt+1:indexEnd]
        if "." in part:
            i = part.index(".")
            return part[i+1:]
        return email[indexAt+1:indexEnd]

    def create_sender_profile(self, num_samples):
        emails_with_sender = 0
        no_messageIDDomain = 0
        new_format_found = 0
        sender_profile = {}
        for i in range(num_samples):
            msg = self.inbox[i]
            if "List-Unsubscribe" in msg.keys():
                continue
            sender = msg["From"]
            if sender:
                emails_with_sender += 1
                mID = self.get_endMessageIDDomain(self.get_messageIDDomain(msg))
                # import pdb; pdb.set_trace()
                if mID == None:
                    no_messageIDDomain += 1
                    if sender not in sender_profile.keys():
                        sender_profile[sender] = set([])
                else:
                    if (scheme_number >= 1 and scheme_number <= 3):
                        if sender in sender_profile.keys():
                            if mID not in sender_profile[sender]:
                                if self.toFlag(sender, mID):
                                    new_format_found += 1
                                    # print(sender, mID, str(sender_profile[sender]))
                                sender_profile[sender].add(mID)
                        else:
                            sender_profile[sender] = set([mID])
                    elif scheme_number == 4:
                        email_domain = self.getEmailDomain(sender)
                        if email_domain not in self.GLOBAL_SET.keys():
                            self.GLOBAL_SET[email_domain] = []

                        if mID not in self.GLOBAL_SET[email_domain]:
                            if (self.GLOBAL_SET[email_domain]):
                                new_format_found += 1
                                # print(sender, mID)
                                self.GLOBAL_SET[email_domain].append(mID)
                            else:
                                self.GLOBAL_SET[email_domain] = [mID]
                    else:
                        sys.exit()
                        raise Exception("The scheme_number is not between 1 and 4 inclusive.")

        self.emails_with_sender = emails_with_sender
        self.no_messageIDDomain = no_messageIDDomain
        self.new_format_found = new_format_found
        # senderProfile = open("sender_profile", "w")
        # senderProfile.write("Sender Profile:\n" + str(sender_profile) + "\n")
        self.sender_profile = sender_profile
        return sender_profile

    def toFlag(self, sender, mID):
        if scheme_number == 1:
            return True
        elif scheme_number == 2:
            return self.checkObviousMID(sender, mID)
        elif scheme_number == 3:
            return self.checkGeneralMID(sender, mID)

class ContentTypeDetector(Detector):
    def __init__(self, inbox):
        self.inbox = inbox
        # [content-type, charset, boundary]
        self.detections = {"content-type": 0, "charset": 0, "boundary": 0}

    def modify_phish(self, phish, msg):
        phish["Content-Type"] = msg["Content-Type"]
        return phish

    def get_content_type(self, msg):
        return self.get_entire_content(msg)[0]

    def get_entire_content(self, msg):
        ctype = msg["Content-Type"]
        if ctype == None:
            return ["None"]
        return ctype.split(";")

    def clean_spaces(self, text):
        return text.strip(" \t\r\n")

    def has_quotes(self, text):
        return re.match("\".*\"", text) is not None

    def strip_quotes(self, text):
        if self.has_quotes(text):
            return text[1:len(text) - 1]
        return text

    def convert_to_binary(self, text):
        res = ""
        if self.has_quotes(text):
            res += "+"
            text = text[1:len(text) - 1]
        for c in text:
            if c in "=-_.?:/":
                res += "0"
            else:
                res += "1"
        return res

    def convert_to_format(self, text):
        return re.sub("[a-zA-Z0-9]+", "@", text)

    def convert_to_partition(self, text):
        res = ""
        curr = ""
        other = "=-_.?:/\""
        alpha_num = "[a-zA-Z0-9]"
        words = ["part", "multipart", "mime", "boundary", "mimepart", "boundary","nextpart", "mcpart", "msg", "border", "b1", "av"]
        pattern = other if text[0] in other else alpha_num
        for c in text:
            if (pattern == other and c in pattern) or (re.match(pattern, c) != None):
                curr += c
            else:
                if pattern == alpha_num and curr not in words:
                    curr = "@"
                pattern = alpha_num if pattern == other else other
                res += curr
                curr = c
        if pattern == alpha_num and curr not in words:
            curr = "@"
        res += curr
        res = self.modify_partition(res)
        return res

    def modify_partition(self, text):
        case1 = ['"-@-@-@=:@"', "-@-@-@=:@"]
        case2 = ['"_av-@-@-@"', '"_av-@-@"', '"_av-@"', "_av-@-@-@", "_av-@-@", "_av-@"]
        if text in case1:
            return text.replace("-", "", 1)
        if text in case2:
            return "_av-@"
        return text

    def process(self, cts):
        #res = {"content-type": None, "charset": None, "boundary": None}
        res = {}
        for attr in cts:
            attr, value = self.get_attr_val(attr)
            if attr == "boundary":
                value = self.convert_to_partition(value)
            res[attr] = value
        return res

    def get_attr_val(self, att_val):
        att_val = att_val.split("=", 1)
        attr = self.clean_spaces(att_val[0])
        value = None
        if len(att_val) == 1:
            # case: plain content_type
            value = attr
            if value == "None":
                self.no_content_type += 1
                value = None
            attr = "content-type"
        else:
            # case: boundary, charset, etc
            value = att_val[1]
        return attr.lower(), None if value is None else value.lower()

    def classify(self, phish):
        sender = self.extract_from(phish)
        entire_ct = self.get_entire_content(phish)
        processed_ct = self.process(entire_ct)
        detect = False
        for attr, value in processed_ct.items():
            if sender in self.sender_profile.keys():
                if attr not in self.sender_profile[sender].keys() or value not in self.sender_profile[sender][attr]:
                    if attr in self.detections.keys():
                        self.detections[attr] += 1
                    detect = True
            else:
                # print("Sender was not found in sender_profile: %s" % (sender))
                pass
        return detect

    def update_sender_profile(self, attr, value, sender):
        new_format = 0
        if sender not in self.sender_profile.keys():
            self.sender_profile[sender] = {}
        if attr not in self.sender_profile[sender].keys():
            self.sender_profile[sender][attr] = set([value])
        else:
            if value not in self.sender_profile[sender][attr]:
                new_format = 1
            self.sender_profile[sender][attr].add(value)
        return new_format

    def update_entire_attribute(self, attr, value):
        if attr not in self.entire_attribute.keys():
            self.entire_attribute[attr] = {}
        if value not in self.entire_attribute[attr].keys():
            self.entire_attribute[attr][value] = 1
        else:
            self.entire_attribute[attr][value] += 1

    def graph_distribution(self):
        self.num_boundary_format_used.insert(0, 0)
        plt.plot([x for x in range(len(self.num_boundary_format_used))] , self.num_boundary_format_used, 'bo', markersize=12)
        plt.xlabel("Total number of boundary formats used")
        plt.ylabel("Number of Senders")
        plt.title("Distribution of Total Boundary Formats used across Senders")
        plt.show()
        return

    def create_sender_profile(self, num_samples):
        self.emails_with_sender = 0
        self.no_content_type = 0
        # [content-type, charset, boundary]
        self.false_alarm = [0, 0, 0]
        self.combined_false = 0
        self.false_alarm = {"content-type": 0, "charset": 0, "boundary": 0}
        self.sender_profile = {}
        self.entire_attribute = {}
        for i in range(num_samples):
            msg = self.inbox[i]
            sender = self.extract_from(msg)
            if sender:
                self.emails_with_sender += 1
                entire_ct = self.get_entire_content(msg)
                processed_ct = self.process(entire_ct)
                new_format = 0
                for attr, value in processed_ct.items():
                    new = self.update_sender_profile(attr, value, sender)
                    new_format += new
                    if new:
                        self.false_alarm[attr] += 1
                    self.update_entire_attribute(attr, value)
            if new_format > 0:
                self.combined_false += 1


    def trim_distributions(self, distr):
        while distr[len(distr)-1] == 0:
            distr = distr[:len(distr)-1]
        return distr

    def analyzing_sender_profile(self):
        num_mult_format = 0
        num_special_format = 0
        special_format = "@"
        for p in self.sender_profile.values():
            if "boundary" in p.keys():
                formats = p["boundary"]
                if len(formats) > 1:
                    num_mult_format += 1
                    if special_format in formats:
                        num_special_format += 1
        print("Number of senders with >1 boundary format = " + str(num_mult_format))
        print("Number of senders with '@' as a format = " + str(num_special_format))
        print("#@ / #>1 = %.2f" % (num_special_format / num_mult_format))

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
