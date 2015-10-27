from detector import Detector
import mailbox
import pprint
import sys


class Content_Type_Detector(Detector):
    def __init__(self, inbox):
        self.inbox = inbox
        self.ori_sender_profile = self.create_sender_profile()

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

    def match_attribute(self, text):
        return text.strip(" \t\r\n")
        
    def classify(self, phish):
        sender = self.extract_from(phish)
        ctype = self.get_content_type(phish)
        if sender in self.ori_sender_profile.keys():
            if ctype not in self.ori_sender_profile[sender]:
                return True
        else:
            print(sender)
            print(self.detected)
            raise Exception("Sender was not found in sender_profile.")
        return False

    def update_sender_profile(self, attr, value, sender):
        if sender not in self.sender_profile.keys():
            self.sender_profile[sender] = {}
        if attr not in self.sender_profile[sender].keys():
            self.new_format_found += 1
            self.sender_profile[sender][attr] = set([value])
        else:
            if value not in self.sender_profile[sender][attr]:
                self.new_format_found += 1
            self.sender_profile[sender][attr].add(value)

    def update_entire_attribute(self, attr, value):
        if attr not in self.entire_attribute.keys():
            self.entire_attribute[attr] = {}
        if value not in self.entire_attribute[attr].keys():
            self.entire_attribute[attr][value] = 1
        else:
            self.entire_attribute[attr][value] += 1

    def create_sender_profile(self):
        self.emails_with_sender = 0
        self.no_content_type = 0
        self.new_format_found = 0
        self.content_types = {}
        self.sender_profile = {}
        self.entire_attribute = {}
        self.ori_sender_profile = {}
        for msg in self.inbox:
            sender = self.extract_from(msg)
            if sender:
                self.emails_with_sender += 1
                entire_ct = self.get_entire_content(msg) 
                for attr in entire_ct:
                    att_val = attr.split("=", 1)
                    attr = self.match_attribute(att_val[0])
                    if len(att_val) == 1:
                        # case: plain content_type
                        value = attr
                        if value == "None":
                            self.no_content_type += 1
                        attr = "content-type"
                    else:
                        # case: boundary, charset, etc
                        value = att_val[1]
                    if attr == "boundary":
                        continue
                    self.update_sender_profile(attr, value, sender)
                    self.update_entire_attribute(attr, value)
                    
                ct = self.get_content_type(msg)
                if ct not in self.content_types:
                    self.content_types[ct] = 1
                else:
                    self.content_types[ct] += 1
                if sender in self.ori_sender_profile.keys():
                    if ct not in self.ori_sender_profile[sender]:
                        self.ori_sender_profile[sender].add(ct)
                else:
                    self.ori_sender_profile[sender] = set([ct])
        pprint.pprint(self.entire_attribute)
        return self.ori_sender_profile 

    def interesting_stats(self):
        distribution_of_num_ct_used = [0,0,0,0,0,0,0,0]
        for cTypes in self.sender_profile.values():
            distribution_of_num_ct_used[len(cTypes) - 1] += 1

        uniqueSenders = len(self.sender_profile.keys())
        total_emails = len(self.inbox)
        singleContent = distribution_of_num_ct_used[0] / uniqueSenders * 100
        multipleContent = ((distribution_of_num_ct_used[1]
                           + distribution_of_num_ct_used[2] 
                           + distribution_of_num_ct_used[3])
                           / uniqueSenders * 100)
        
        for k in self.content_types:
            print("%s : %d ~ %.2f" % (k, self.content_types[k], self.content_types[k]/total_emails * 100) + "%")

        print("Total emails = " + str(total_emails))
        print("Emails with sender = " + str(self.emails_with_sender))
        print("Emails with no content type = " + str(self.no_content_type))
        print("unique Senders = " + str(uniqueSenders))
        print("distribution_of_num_ct_used = " + str(distribution_of_num_ct_used))
        print("new_format_found = " + str(self.new_format_found))
        print("false alarm rate = %.2f percent" % (self.new_format_found / self.emails_with_sender * 100 ))
        print("percent of senders with only 1 CT, 1+ CT = %.3f, %.3f" % (singleContent, multipleContent))
    

def printInfo(msg):
    print(msg["From"])
    print(msg["Content-Type"])
    print(msg["Subject"])

file_name = "~/emails/Inbox500.mbox"
inbox = mailbox.mbox(file_name)
d = Content_Type_Detector(inbox)
d.interesting_stats()
print("detection rate = " + str(d.run_trials()))
