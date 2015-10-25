from detector import Detector
import mailbox
import pprint
import sys

class Content_Type_Detector(Detector):
    def __init__(self, inbox):
        self.inbox = inbox
        self.sender_profile = self.create_sender_profile()

    def check_header(self, msg):
        ctype = msg["Content-Type"]
        return ctype is not None

    def modify_phish(self, phish, msg):
        phish["Content-Type"] = msg["Content-Type"]
        return phish

    def get_content_type(self, msg):
        ctype = msg["Content-Type"]
        if ctype == None:
            return None
        return ctype.split(";")[0]
        
    def classify(self, phish):
        sender = self.extract_from(phish)
        ctype = self.get_content_type(phish)
        if ctype == None:
            if len(self.sender_profile[sender]) == 0:
                return False
       # finish 
        if sender in self.sender_profile.keys():
            if ctype not in self.sender_profile[sender]:
                return True
        else:
            print(sender)
            print(self.detected)
            sys.exit()
            raise Exception("Sender was not found in sender_profile.")
        return False

    def create_sender_profile(self):
        emails_with_sender = 0
        no_content_type = 0
        new_format_found = 0
        content_types = {}
        sender_profile = {}
        for msg in self.inbox:
            sender = self.extract_from(msg)
            if sender:
                emails_with_sender += 1
                ct = self.get_content_type(msg) 
                if ct == None:
                    no_content_type += 1
                    if sender not in sender_profile.keys():
                        sender_profile[sender] = set([])
                    continue
                if ct not in content_types:
                    content_types[ct] = 1
                else:
                    content_types[ct] += 1
                if sender == "the_autograder" or sender == "hiring@rescomp.berkeley.edu":
                    print("FOUNNND====")
                    print(sender)
                if sender in sender_profile.keys():
                    if ct not in sender_profile[sender]:
                        new_format_found += 1
                        sender_profile[sender].add(ct)
                else:
                    sender_profile[sender] = set([ct])
                    if sender == "the_autograder" or sender == "hiring@rescomp.berkeley.edu":
                        print("added to senderprofile =====")
                        print(sender)
        self.content_types = content_types
        self.emails_with_sender = emails_with_sender
        self.no_content_type = no_content_type
        self.new_format_found = new_format_found
        return sender_profile 

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
