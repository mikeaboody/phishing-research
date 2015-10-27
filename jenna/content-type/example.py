from sys import argv
import mailbox
import pylab as pl
import numpy as np
import re
import sys
import email.utils
from functools import reduce
import pprint
from random import randint

class Sender:
    def __init__(self, email):
        self.email = email
        self.emails = []

contentTypes = {}
senderToContentType = {}

def printInfo(msg):
    print(msg["From"])
    print(msg["Content-Type"])
    print(msg["Subject"])
    print(msg["Date"])

class Detector:
    def __init__(self, inbox, senderToContentType):
        self.inbox = inbox
        self.senderValMap = senderToContentType
        self.initialSize = len(inbox)
    
    def makePhish(self, template, fromLine):
        phish = mailbox.mboxMessage()
        phish['From'] = fromLine['From']
        phish['To'] = template['To']
        phish['Subject'] = template['Subject'] 
        phish['Content-Type'] = template['Content-Type'] 
        phish.set_payload("This is the body for a generated phishing email.\n")
        return phish

    def insertPhish(self):
        hasSender1, hasSender2 = None, None
        randomMsg = None
        randomFrom = None
        while not hasSender1 or not hasSender2:
            randomMsg = self.inbox[randint(0, len(self.inbox)-1)]
            randomFrom = self.inbox[randint(0, len(self.inbox)-1)]
            hasSender1 = extractFrom(randomMsg)
            hasSender2 = extractFrom(randomFrom)
        phish = self.makePhish(randomMsg, randomFrom)
        self.inbox.add(phish)
        self.inbox.flush()

        length = len(self.inbox) - 1
        randLoc = randint(0, length - 1)
        self.inbox[randLoc], self.inbox[length] = phish, self.inbox[randLoc]
        self.phish = phish
        self.phishLocation = randLoc
        
    def deletePhish(self):
        assert self.phish != None
        assert self.phishLocation != None
        randLoc = self.phishLocation
        phish = self.phish
        length = len(self.inbox) - 1
        self.inbox[length], self.inbox[randLoc] = self.inbox[randLoc], self.inbox[length]
        self.inbox.remove(length)
        self.inbox.flush()
        self.phish = None
        self.phishLocation = None
        assert self.initialSize == len(self.inbox)
        saveKey = []
        for key, msg in self.inbox.items():
            if msg["Subject"] == phish["Subject"] and msg["From"] == phish["From"] and msg["To"] == phish["To"]:
                saveKey.append(key)
        if len(saveKey) > 0:
            print("Unexpected error, did not delete phish?")
        for key in saveKey:
            self.inbox.remove(key)

    def detectPhish(self):
        phisher = extractFrom(self.phish)
        contentType = self.phish['Content-Type']
        if contentType not in self.senderValMap[phisher]:
            return True
        return False
    
    def runTrials(self, x):
        detected = 0
        for i in range(x):
            self.insertPhish()
            print(i)
            if self.detectPhish():
                detected += 1
            self.deletePhish()
        return detected / x * 100

        

class Analyzer:
    def __init__(self, file_name):
        self.email = "jenna.r.tan@gmail.com"
        self.name = "jenna tan"
        self.box = mailbox.mbox(file_name + ".mbox")
       # saveKey = []
       # i = 0
       # for key, msg in self.box.items():
       #     if i < 21288:
       #         saveKey.append(key)
       #         i += 1
       #     else:
       #         break
       # for key in saveKey:
       #     self.box.remove(key)
       # self.box.flush()
        print(len(self.box))

        print("Analyzing...")
        senderToContentType = self.analyze()
        #detector = Detector(self.box, senderToContentType)
        print("Detecting phish...")
        #detector.runTrials(100)
        print("Finished Analyzing.")

    def analyze(self):
        i = 0
        total = 0
        noCT = 0
        count = 0
        for msg in self.box:
            total += 1
            sender = extractFrom(msg)
            if sender:
                #initializing
                ct = msg["Content-Type"]
                tfe = msg["Content-Transfer-Encoding"]
                #if tfe != None:
                #    print(tfe)
                #    print("FOUND TFE IN HEADER")
                #    sys.exit()
                if ct == None:
                    noCT += 1
                    continue
                ct = ct.split(";")[0]   
                if ct not in contentTypes:
                    contentTypes[ct] = 1
                else:
                    contentTypes[ct] += 1
                
                if sender in senderToContentType:
                    if ct not in senderToContentType[sender]:
                        count += 1
                    senderToContentType[sender].add(ct)
                   # if senderToContentType[sender][0] != ct:
                   #     count += 1
                   # if ct not in senderToContentType[sender]:
                   #     senderToContentType[sender].append(ct)
                else:
                    senderToContentType[sender] = set([ct])
                    #senderToContentType[sender] = [ct]
                i += 1
        numUsers = [0,0,0,0,0,0,0,0]
        for cTypes in senderToContentType.values():
            numUsers[len(cTypes) - 1] += 1
        uniqueSenders = reduce(lambda x,y: x + y, numUsers)
        print("UNIQUE SENDER = " + str(uniqueSenders))
        print("is this the same?? " + str(len(senderToContentType.keys())))
        multipleContent = (numUsers[1] + numUsers[2] + numUsers[3]) / uniqueSenders * 100
        singleContent = numUsers[0] / uniqueSenders * 100
        pprint.pprint(contentTypes, width=1)
        for k in contentTypes:
            print("%s : %d ~ %.3f" % (k, contentTypes[k], contentTypes[k]/total * 100) + "%")
        print("Total = " + str(total))
        print("withSender = " + str(i))
        print("No content type = " + str(noCT))
        print("unique Senders = " + str(uniqueSenders))
        print("numUsers = " + str(numUsers))
        print("count = " + str(count))
        print("false alarm rate = %.2f" % (count / i * 100 ))
        print("percent of senders with only 1 CT, 1+ CT = %.3f, %.3f" % (singleContent, multipleContent))
        return senderToContentType


def extractFrom(msg):
    from_header = msg["From"]
    if not from_header:
        return None
    from_header = from_header.lower()
    r = re.compile(" *<.*> *")
    from_header = r.sub("", from_header)
    r = re.compile("^ +")
    from_header = r.sub("", from_header)
    return from_header

file_name = "~/emails/Inbox"
a = Analyzer(file_name)
#\d+(\.\d+)+
#extract everything in brackets, parenthesis, etc
#extract everything that looks like a version number
#cut off all first words as apart of similarity
#prefix matching in similarity
#perhaps try word COUNTING in similarity

#(), **, "- " "", [], <>, "ver" ""
#spaces
#version number




#    def analyze(self):
#        i = 0
#        for msg in self.box:
#            curr_name = extract_name(msg)
#            if curr_name:
#                #initializing
#                ct = msg["Content-Type"].split(";")[0]
#                if ct not in contentTypes:
#                    contentTypes[ct] = 1
#                else:
#                    contentTypes[ct] += 1
#                i += 1
#                continue
#                curr_xmailer = getXMailer(msg)
#                #general
#                if curr_name != self.name:
#                    self.emails_other_than_mine.add(msg)
#                similar_xmailer = getSimilar(curr_xmailer, self.general_xmailer_distribution.keys())
#                if not similar_xmailer:
#                    self.general_xmailer_distribution[curr_xmailer] = self.general_xmailer_distribution.get(curr_xmailer, 0)
#                    similar_xmailer = curr_xmailer
#                self.general_xmailer_distribution[similar_xmailer] += 1
#                #per sender
#                curr_sender = self.names_to_senders.get(curr_name, Sender(curr_name))
#                similar_xmailer = getSimilar(curr_xmailer, curr_sender.xmailer_distribution.keys())
#                if not similar_xmailer:
#                    curr_sender.xmailer_distribution[curr_xmailer] = curr_sender.xmailer_distribution.get(curr_xmailer, 0)
#                    similar_xmailer = curr_xmailer
#                curr_sender.xmailer_distribution[similar_xmailer] += 1
#                curr_sender.emails.append(msg)
#                #finalize
#                self.names_to_senders[curr_name] = curr_sender
#
#            pprint.pprint(contentTypes, width=1)
#            print(i)
#            sys.exit()
#    def getNamesToSenders(self):
#        return self.names_to_senders
#    def getGeneralXMailerDistribution(self):
#        return self.general_xmailer_distribution
#    def runStatistics(self):
#        senders = self.getNamesToSenders()
#        consistent = 0
#        inconsistent = 0
#        doesnt_use = 0
#        unreliable = 0
#        for s in senders:
#            curr_sender = senders[s]
#            curr_mailers = curr_sender.xmailer_distribution.keys()
#            if None in curr_mailers:
#                if len(curr_mailers) == 1:
#                    doesnt_use += 1
#                else:
#                    unreliable += 1
#            else:
#                if len(curr_mailers) == 1:
#                    consistent += 1
#                else:
#                    inconsistent += 1
#
#        #how many emails do you have (after removing all the ones you've sent)?
#        print("How many emails do you have (after removing all the one's you've sent)?", len(self.emails_other_than_mine))
#        #how many have an X-Mailer header?
#        #what's the distribution of X-Mailer header values
#        for x in self.general_xmailer_distribution:
#            print(str(x) + ":", self.general_xmailer_distribution[x])
#        #GRAPH
#        d = self.general_xmailer_distribution
#        X = np.arange(len(d))
#        pl.bar(X, d.values(), align='center', width=0.5)
#        pl.xticks(X, [i for i in range(len(d.keys()))])
#        ymax = max(d.values()) + 1
#        pl.ylim(0, ymax)
#        pl.show()
#        #UNGRAPH
#        print ("=======================================================")
#        #per-sender
#        #how many senders?
#        print("How Many Senders?", consistent + inconsistent + doesnt_use + unreliable)
#        #how many senders have no email with a X-Mailer?
#        print("How Many Senders Have No Email With a X-Mailer?", doesnt_use)
#        #how many senders have a X-Mailer on every email?
#        print("How Many Senders Have a X-Mailer on every email?", consistent + inconsistent)
#        #how many senders have a X-Mailer on some emails but not others?
#        print ("How Many Senders Have a X-Mailer on Some Emails But Not Others?", unreliable)
#        #for each sender compute the fraction of their emails that have a X-Mailer header and then plot a histogram of its distribution
#        #Look at consistency of X-Mailer per sender, and over time per sender
#        print ("=======================================================")
#        print("Look at consistency of X-Mailer per sender")
#        print("How many senders are consistent with their use of X-Mailer?", consistent)
#        print("How many senders are inconsistent with their use of X-Mailer?", inconsistent)
#        print("For all inconsistent senders, here are their distributions")
#        self.inconsistentUserDistributions()
#    def inconsistentUserDistributions(self):
#        senders = self.getNamesToSenders()
#        for s in senders:
#            curr_sender = senders[s]
#            curr_mailers = curr_sender.xmailer_distribution.keys()
#            if len(curr_mailers) > 1:
#                print("=========")
#                print("Sender: ", s)
#                print("Distribution:")
#                for x in curr_sender.xmailer_distribution:
#                    print(str(x) + ":", curr_sender.xmailer_distribution[x])
#
#def extractVersion(xmailer):
#    r = re.compile("\d+(\.\d+)+")
#    return r.sub("", xmailer)
#def extractParentheticals(xmailer):
#    pairings = [("\(", "\)"), ("\[", "\]"), ("\*", "\*"), ("<", ">"), ("\- ", ""), ("ver", ""), ("\(", ""), (" \d", "")]
#    for left, right in pairings:
#        exp = left + ".*" + right
#        r = re.compile(exp)
#        xmailer = r.sub("", xmailer)
#    return xmailer
#
#def removeSpaces(xmailer):
#    exp = " +$"
#    r = re.compile(exp)
#    xmailer = r.sub("", xmailer)
#    return xmailer
#
#def getXMailer(msg):
#    xmailer = msg["X-Mailer"]
#    return None if not xmailer else removeSpaces(extractVersion(extractParentheticals(xmailer)))
#
#def getSimilar(given_str, given_set):
#    for s in given_set:
#        # if s and given_str and Levenshtein.ratio(given_str, s) > 0.9:
#        if s and given_str and given_str.lower() == s.lower():
#            return s
#    return None
