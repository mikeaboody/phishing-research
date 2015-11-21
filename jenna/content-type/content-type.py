from detector import Detector
import mailbox
import re
import functools
import pprint
import sys
import matplotlib.pyplot as plt

class Content_Type_Detector(Detector):
    def __init__(self, inbox):
        self.inbox = inbox
        self.create_sender_profile()
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
                print("Sender was not found in sender_profile: %s" % (sender))
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
    
    def create_sender_profile(self):
        self.emails_with_sender = 0
        self.no_content_type = 0
        # [content-type, charset, boundary]
        self.false_alarm = [0, 0, 0]
        self.combined_false = 0
        self.false_alarm = {"content-type": 0, "charset": 0, "boundary": 0}
        self.sender_profile = {}
        self.entire_attribute = {}
        for msg in self.inbox:
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
        pprint.pprint(self.entire_attribute)
        print(self.false_alarm)
        print(len(self.entire_attribute["boundary"]))

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


    def interesting_stats(self):
        num_ct_used = [0]*10
        num_charset_used = [0]*10
        num_boundary_format_used = [0]*10
        troll = 0
        for distr in self.sender_profile.values():
            for attr in distr.keys():
                values = distr[attr]
                num_formats = len(values) - 1
                if attr == "content-type":
                    num_ct_used[num_formats] += 1
                elif attr == "charset":
                    num_charset_used[num_formats] += 1
                elif attr == "boundary":
                    total_len = len(num_boundary_format_used)
                    if num_formats >= total_len:
                        num_boundary_format_used.extend([0] * (num_formats - total_len + 1))
                    num_boundary_format_used[num_formats] += 1
        self.num_ct_used = self.trim_distributions(num_ct_used)
        self.num_charset_used = self.trim_distributions(num_charset_used)
        self.num_boundary_format_used = self.trim_distributions(num_boundary_format_used)
        uniqueSenders = len(self.sender_profile.keys())
        total_emails = len(self.inbox)
        singleContent = self.num_ct_used[0] / uniqueSenders * 100
        multipleContent = (functools.reduce(lambda x, y : x + y, self.num_ct_used[1:]) / uniqueSenders * 100)
        
        four = (functools.reduce(lambda x, y : x + y, self.num_boundary_format_used[:4])) / uniqueSenders * 100
        ct_table = self.entire_attribute["content-type"] 
        for k in ct_table:
            print("%s : %d ~ %.2f" % (k, ct_table[k], ct_table[k]/total_emails * 100) + "%")

        print("Total emails = " + str(total_emails))
        print("Emails with sender = " + str(self.emails_with_sender))
        print("Emails with no content type = " + str(self.no_content_type))
        print("unique Senders = " + str(uniqueSenders))
        print("distribution_of_num_ct_used = " + str(self.num_ct_used))
        print("distribution_of_num_charset_used = " + str(self.num_charset_used))
        print("distribution_of_num_boundary_format_used = " + str(self.num_boundary_format_used))
        print("new_ct_formats = " + str(self.false_alarm["content-type"]))
        print("false alarm rate Content-Type = %.2f percent" % (self.false_alarm["content-type"] / self.emails_with_sender * 100 ))
        print("false alarm rate Charset types = %.2f percent" % (self.false_alarm["charset"] / self.emails_with_sender * 100 ))
        print("false alarm rate Boundary format = %.2f percent" % (self.false_alarm["boundary"] / self.emails_with_sender * 100 ))
        print("combined false alarm rate = %.2f percent" % (self.combined_false / self.emails_with_sender * 100 ))
        print("percent of senders with only 1 CT, 1+ CT = %.3f, %.3f" % (singleContent, multipleContent))
        print("percent of senders with <=4 boundary formats used = %.3f" % (four))

def printInfo(msg):
    print(msg["From"])
    print(msg["Content-Type"])
    print(msg["Subject"])

file_name = "~/emails/Inbox.mbox"
inbox = mailbox.mbox(file_name)
d = Content_Type_Detector(inbox)
d.interesting_stats()
d.analyzing_sender_profile()
#d.graph_distribution()
print("combined detection rate = " + str(d.run_trials()))
print("detection for content-type = " + str(d.detections["content-type"] / 10))
print("detection for charset = " + str(d.detections["charset"] / 10))
print("detection for boundary = " + str(d.detections["boundary"] / 10))
