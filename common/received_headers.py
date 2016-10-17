from detector import Detector
import sys
import re
import pdb
from netaddr import IPNetwork, IPAddress
import editdistance
import os
from lookup import Lookup



class SenderReceiverPair:
    def __init__(self, sender, receiver):
        self.receiver = receiver
        self.sender = sender
        self.emailList = []
        self.received_header_sequences = []
    def __str__(self):
        s = ""
        for email in self.emailList:
            s += str(email) + "\n"
        return s

class Email:
    def __init__(self):
        self.receivedHeaderList = []

    def __str__(self):
        s = ""
        for rh in self.receivedHeaderList:
            s += str(rh) + " | "
        return s
        
class ReceivedHeader:

    def __init__(self, content):
        self.createBreakdown(content)
        
    def createBreakdown(self, content):
        #very simple breakdown scheme for receiver headers
        content_split = content.split("\n")
        content = ""
        for s in content_split:
            content += s
        content_split = content.split("\r")
        content = ""
        for s in content_split:
            content += s
        content_split = content.split("\t")
        content = ""
        for s in content_split:
            content += s
        breakdown = {}
        possible_fields = ["from", "by", "via", "with", "id", "for", ";", "$"]
        for i in range(len(possible_fields)):
            start = possible_fields[i]
            for j in range(i+1, len(possible_fields)):
                end = possible_fields[j]
                r = re.search(start + " +(.*) *" + end, content)
                if r:
                    match = r.group(1)
                    breakdown[start] = removeSpaces(match)
                    break
        self.breakdown = breakdown
        if ";" in self.breakdown:
            self.breakdown["date"] = self.breakdown[";"]
            del self.breakdown[";"]

    def assignCIDR(self):
        if not "from" in self.breakdown.keys():
            return "None"
        elif Lookup.public_domain(self.breakdown["from"]):
            ip = Lookup.public_domain(self.breakdown["from"])
        elif Lookup.public_IP(self.breakdown["from"]):
            ip = Lookup.public_IP(self.breakdown["from"])
        else:
            return "Invalid"
        return Lookup.getCIDR(ip)

    def __str__(self):
        return str(self.breakdown)

class SenderReceiverProfile(dict):

    def __init__(self, inbox, num_samples, detector):
        self.inbox = inbox
        self.detector = detector
        self.analyze(num_samples)

    def analyze(self, num_samples):
        count = 0
        for msg in self.inbox:
            self.appendEmail(msg)
            count += 1
            if count >= num_samples:
                break
        self.createReceivedHeaderSequences()

    def appendEmail(self, msg):
        sender = extract_email(self.detector.extract_from(msg))
        receiver = ""
        if (sender, receiver) not in self:
            self[(sender, receiver)] = SenderReceiverPair(sender, receiver)
        srp = self[(sender, receiver)]
        newEmail = Email()
        if (len(msg.get_all("Received")) != 0):
            for receivedHeader in msg.get_all("Received"):
                rh = ReceivedHeader(receivedHeader)
                newEmail.receivedHeaderList.append(rh)
            srp.emailList.append(newEmail)

    def createReceivedHeaderSequences(self):
        for tup, srp in self.items():
            seq_rh_from = []
            for em in srp.emailList:
                num_recHeaders = len(em.receivedHeaderList)
                RHList = []
                for recHeader in em.receivedHeaderList:
                    RHList.append(recHeader.assignCIDR())
                if RHList not in seq_rh_from:
                    seq_rh_from.append(RHList)
            srp.received_header_sequences = seq_rh_from

    def writeReceivedHeadersToFile(self):
        FILE = open("receivedHeaders", "a")
        for tup, srp in self.items():
            FILE.write("SRP******************************************\n")
            FILE.write(str(tup) + ":\n")
            for em in srp.emailList:
                FILE.write("@@@------------------------------------------\n")
                for rh in em.receivedHeaderList:
                    FILE.write(str(rh) + "\n")
            FILE.write("------------------------------------------\n")

class ReceivedHeadersDetector(Detector):
    NUM_HEURISTICS = 3

    def __init__(self, inbox):
        self.inbox = inbox

    def modify_phish(self, phish, msg):
        phish["Received"] = None
        if len(msg.get_all("Received")) != 0:
            phish["Received"] = []
            recHeaders = msg.get_all("Received")[:]
            for i in range(len(recHeaders)):
                phish["Received"].append(recHeaders[i])
        return phish

    def classify(self, phish):
        RHList = []
        sender = extract_email(self.extract_from(phish))
        receiver = ""
        edit_distances = [0, 1, 2]
        feature_vector = [0 for _ in range(len(edit_distances))]

        if (sender, receiver) not in self.srp:
            return feature_vector

        # creating the received header list for this email
        srp = self.srp[(sender, receiver)]
        if len(phish.get_all("Received")) != 0:
            for recHeader in phish.get_all("Received"):
                recHeader = ReceivedHeader(recHeader)
                RHList.append(recHeader.assignCIDR())
        
        # checking to see if there is a "matching" received header
        # list for this SRP
        for i, threshold in enumerate(edit_distances):
            if RHList not in srp.received_header_sequences:
                if srp.received_header_sequences:
                    bestEditDist = None
                    for lst in srp.received_header_sequences:
                        ed = editdistance.eval(RHList, lst)
                        if bestEditDist == None or bestEditDist > ed:
                            bestEditDist = ed
                    if bestEditDist > threshold:
                        feature_vector[i] = 1
        return feature_vector

    def create_sender_profile(self, num_samples):
        self.srp = SenderReceiverProfile(self.inbox, num_samples, self)

def extract_email(from_header):
    if not from_header:
        return None
    from_header = from_header.lower()
    r = re.search("([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)", from_header)
    return r.group() if r else from_header

def removeSpaces(s):
    exp = " +$"
    r = re.compile(exp)
    s = r.sub("", s)
    exp = "^ +"
    r = re.compile(exp)
    s = r.sub("", s)
    return s
