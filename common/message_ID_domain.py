from detector import Detector
import sys, re, os

# IPWhois
# import socket
# from ipwhois import IPWhois
from lookup import Lookup

class messageIDDomain_Detector(Detector):
    GLOBAL_SET = {} # email domain : [MID domain 0, ...]
    domainCompanyPairing = {} # domain : company
    domain2domainPairing = {}
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
        return mID
        
    def classify(self, phish):
        sender = self.getEntireEmail(self.extract_from(phish))
        mID = self.get_endMessageIDDomain(self.get_messageIDDomain(phish))

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
        if "@" not in email:
            return email
        indexAt = email.index("@")
        if "." not in (email[indexAt:])[::-1]:
            return email[indexAt+1:]
        indexEnd = (len(email)-indexAt) - (email[indexAt:])[::-1].index(".") + indexAt - 1
        part = email[indexAt+1:indexEnd]
        if "." in part:
            i = part.index(".")
            return part[i+1:]
        return email[indexAt+1:indexEnd]

    # returns apoorva.dornadula@berkeley.edu given "Apoorva Dornadula <apoorva.dornadula@berkeley.edu>"
    def getEntireEmail(self, sender):
        if sender == None:
            return None
        if ("<" in sender and ">" in sender):
            leftBracket = sender.index("<")
            rightBracket = sender.index(">")
            return sender[leftBracket+1:rightBracket]
        return sender

    # returns True if FP and email will not be flagged
    def noreplyFP(self, sender, messageID):
        if messageID == None:
            return False
        pattern = re.compile("no.*reply")
        if pattern.match(sender):
            # noreply case
            if "ismtpd" in messageID or ".mail" in messageID:
                return True
        return False

    def orgGroups(self, sender, mID):
        try:
            newmID = mID
            afterAT = mID
            afterAT = sender[sender.index("@")+1:]

            # if I have seen this pairing before, do not flag as FP
            if (newmID, afterAT) in self.domain2domainPairing:
                return True

            # check domain org match if I can find both domains in my pairings
            if newmID in Lookup.seen_domain_org and afterAT in Lookup.seen_domain_org:
                if Lookup.seen_domain_org[newmID] == Lookup.seen_domain_org[afterAT]:
                    self.domain2domainPairing[(newmID, afterAT)] = True
                    return True
                else:
                    self.domain2domainPairing[(newmID, afterAT)] = False
                    return False

            # if the domains are not in the file, then use CIDR blocks
            if newmID in self.domainCompanyPairing.keys():
                res11 = self.domainCompanyPairing[newmID]
            else:
                # createDomain2OrgPair(newmID)
                ip1 = Lookup.seen_domain_ip[newmID]
                res11 = getBinaryRep(ip1, Lookup.getCIDR(ip1))
                self.domainCompanyPairing[newmID] = res11

            if afterAT in self.domainCompanyPairing.keys():
                res22 = self.domainCompanyPairing[afterAT]
            else:
                # createDomain2OrgPair[afterAT]
                ip2 = Lookup.seen_domain_ip[afterAT]
                res22 = getBinaryRep(ip2, Lookup.getCIDR(ip2))
                self.domainCompanyPairing[afterAT] = res22

            if res11 == res22:
                self.domain2domainPairing[(newmID, afterAT)] = True
                return True
            self.domain2domainPairing[(newmID, afterAT)] = False
            return False
        except:
            self.domain2domainPairing[(newmID, afterAT)] = False
            return False

    def create_sender_profile(self, numSamples):
        emails_with_sender = 0
        no_messageIDDomain = 0
        new_format_found = 0
        self.sender_profile = {}
        # for msg in self.inbox:
        for i in range(numSamples):
            msg = self.inbox[i]
            # if "List-Unsubscribe" in msg.keys():
            #     continue
            sender = self.getEntireEmail(self.extract_from(msg))
            if sender:
                emails_with_sender += 1
                mID = self.get_endMessageIDDomain(self.get_messageIDDomain(msg))
                if mID == None:
                    no_messageIDDomain += 1
                    if sender not in self.sender_profile.keys():
                        self.sender_profile[sender] = set([])
                    self.sender_profile[sender].add("None")
                else:
                    wasntInSenderProfile = False
                    if sender in self.sender_profile.keys():
                        if mID not in self.sender_profile[sender]:
                            if self.toFlag(sender, mID):
                                wasntInSenderProfile = True
                            self.sender_profile[sender].add(mID)
                    else:
                        self.sender_profile[sender] = set([mID])
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
        return self.sender_profile

    def toFlag(self, sender, mID):
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

# returns False if whois lookup is not successful
def createDomain2OrgPair(domain):
    FILE = open("domain2Org.txt", "a")
    try:
        ip1 = socket.gethostbyname(domain)
        obj1 = IPWhois(ip1)
        res1 = obj1.lookup(get_referral=True)['nets'][0]['name']
        FILE.write(domain + " " + res1 + "\n")
        return True
    except:
        return False