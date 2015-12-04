from detector import Detector
import mailbox
import pprint
import sys

class messageIDDomain_Detector(Detector):
    GLOBAL_SET = {} # email domain : [MID domain 0, ...]
    def __init__(self, inbox):
        self.inbox = inbox
        self.sender_profile = self.create_sender_profile()

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

        if "List-Unsubscribe" in phish.keys() or myEmail in phish["From"]:
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

    def create_sender_profile(self):
        emails_with_sender = 0
        no_messageIDDomain = 0
        new_format_found = 0
        sender_profile = {}
        for msg in self.inbox:
            if "List-Unsubscribe" in msg.keys() or myEmail in msg["From"]:
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
                                    print(sender, mID, str(sender_profile[sender]))
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
                                print(sender, mID)
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
        return sender_profile

    def toFlag(self, sender, mID):
        if scheme_number == 1:
            return True
        elif scheme_number == 2:
            return self.checkObviousMID(sender, mID)
        elif scheme_number == 3:
            return self.checkGeneralMID(sender, mID)

    def interesting_stats(self):
        distribution_of_num_mID_used = [0]*70
        for e, mIDs in self.sender_profile.items():
            distribution_of_num_mID_used[len(mIDs) - 1] += 1

        uniqueSenders = len(self.sender_profile.keys())
        total_emails = len(self.inbox)
        singleContent = distribution_of_num_mID_used[0]*1.0 / uniqueSenders * 100.0
        multipleContent = 0
        for m in distribution_of_num_mID_used[1:]:
            multipleContent += m
        multipleContent = (multipleContent*1.0 / uniqueSenders)*100.0
        
        print("Total emails = " + str(total_emails))
        print("Emails with sender = " + str(self.emails_with_sender))
        print("Emails with no message ID domains = " + str(self.no_messageIDDomain))
        print("unique Senders = " + str(uniqueSenders))
        print("distribution_of_num_mID_used = " + str(distribution_of_num_mID_used))
        print("new_format_found = " + str(self.new_format_found))
        print("False alarm rate = %.9f percent" % (self.new_format_found*1.0 / self.emails_with_sender * 100.0 ))
        print("Percent of senders with only 1 message ID Domain, 1 + message ID Domain = %.3f, %.3f" % (singleContent, multipleContent))
    

def printInfo(msg):
    print(msg["From"])
    print(msg["Message-ID"])
    print(msg["Subject"])

file_name = "/home/apoorva/Documents/Research/PhishingResearch/Inbox.mbox"
myEmail = "nexusapoorvacus19@gmail.com"
scheme_number = 3 
inbox = mailbox.mbox(file_name)
d = messageIDDomain_Detector(inbox)
d.interesting_stats()
print("Detection rate = " + str(d.run_trials()))