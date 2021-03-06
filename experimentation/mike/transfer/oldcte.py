from sys import argv
import mailbox
import pylab as pl
import numpy as np
import re
import random

class Sender:
    def __init__(self, email):
        self.email = email
        self.emails = []
        self.xmailer_distribution = {}


class Experiment:
    def __init__(self):
        self.values = {}


class Analyzer:
    def __init__(self, file_name):
        self.email = "mikeaboody@berkeley.edu"
        self.name = "mike aboody"
        self.box = mailbox.mbox(file_name + ".mbox")
        self.names_to_senders = {}
        self.general_xmailer_distribution = {}
        self.emails_other_than_mine = set()
        self.experiment = Experiment()
        print("Analyzing...")
        self.analyze()
        print("Finished Analyzing.")

    def analyze(self):
        self.experiment.values["detected"] = 0
        self.experiment.values["valid-to-detect"] = 0
        randomEmailData = randomEmailGenerator(self.box)
        for i in range(len(self.box)):
            msg = self.box[i]
            curr_name = extract_name(msg)
            if curr_name:
                # initializing
                curr_xmailer = getXMailer(msg)
                # general
                if curr_name != self.name:
                    self.emails_other_than_mine.add(msg)
                similar_xmailer = getSimilar(curr_xmailer, self.general_xmailer_distribution.keys())
                if similar_xmailer == False:
                    self.general_xmailer_distribution[curr_xmailer] = 0
                    similar_xmailer = curr_xmailer
                self.general_xmailer_distribution[similar_xmailer] += 1
                # per sender
                curr_sender = self.names_to_senders.get(curr_name, Sender(curr_name))
                similar_xmailer = getSimilar(curr_xmailer, curr_sender.xmailer_distribution.keys())
                if similar_xmailer == False:
                    if len(curr_sender.xmailer_distribution.keys()) != 0:
                        self.experiment.values["false-alarm"] = self.experiment.values.get("false-alarm", 0) + 1
                    curr_sender.xmailer_distribution[curr_xmailer] = 0
                    similar_xmailer = curr_xmailer
                curr_sender.xmailer_distribution[similar_xmailer] += 1
                curr_sender.emails.append(msg)
                # finalize
                self.names_to_senders[curr_name] = curr_sender
                self.experiment.values["email-count"] = self.experiment.values.get("email-count", 0) + 1

                #random attack
                random_name, random_xmailer = randomEmailData()
                random_sender = self.names_to_senders.get(random_name, None)
                if random_sender:
                    similar_xmailer = getSimilar(random_xmailer, random_sender.xmailer_distribution.keys())
                    if similar_xmailer == False and len(random_sender.xmailer_distribution.keys()) != 0:
                        self.experiment.values["detected"] += 1
                    self.experiment.values["valid-to-detect"] += 1

    def getNamesToSenders(self):
        return self.names_to_senders

    def getGeneralXMailerDistribution(self):
        return self.general_xmailer_distribution

    def runStatistics(self):
        senders = self.getNamesToSenders()
        consistent = 0
        inconsistent = 0
        doesnt_use = 0
        unreliable = 0
        for s in senders:
            curr_sender = senders[s]
            curr_mailers = curr_sender.xmailer_distribution.keys()
            if None in curr_mailers:
                if len(curr_mailers) == 1:
                    doesnt_use += 1
                else:
                    unreliable += 1
            else:
                if len(curr_mailers) == 1:
                    consistent += 1
                else:
                    inconsistent += 1

        # how many emails do you have (after removing all the ones you've sent)?
        print("How many emails do you have (after removing all the one's you've sent)?",
              len(self.emails_other_than_mine))
        # how many have an X-Mailer header?
        # what's the distribution of X-Mailer header values
        for x in self.general_xmailer_distribution:
            print(str(x) + ":", self.general_xmailer_distribution[x])
        # GRAPH
        d = self.general_xmailer_distribution
        X = np.arange(len(d))
        pl.bar(X, d.values(), align='center', width=0.5)
        pl.xticks(X, [i for i in range(len(d.keys()))])
        ymax = max(d.values()) + 1
        pl.ylim(0, ymax)
        pl.show()
        # UNGRAPH
        print("=======================================================")
        # per-sender
        # how many senders?
        print("How Many Senders?", consistent + inconsistent + doesnt_use + unreliable)
        # how many senders have no email with a X-Mailer?
        print("How Many Senders Have No Email With a X-Mailer?", doesnt_use)
        # how many senders have a X-Mailer on every email?
        print("How Many Senders Have a X-Mailer on every email?", consistent + inconsistent)
        # how many senders have a X-Mailer on some emails but not others?
        print("How Many Senders Have a X-Mailer on Some Emails But Not Others?", unreliable)
        # for each sender compute the fraction of their emails that have a X-Mailer header and then plot a histogram of its distribution
        # Look at consistency of X-Mailer per sender, and over time per sender
        print("=======================================================")
        print("Look at consistency of X-Mailer per sender")
        print("How many senders are consistent with their use of X-Mailer?", consistent)
        print("How many senders are inconsistent with their use of X-Mailer?", inconsistent)
        print("For all inconsistent senders, here are their distributions")
        self.inconsistentUserDistributions()
        self.runExperiment()

    def runExperiment(self):
        num_of_false_alarms = self.experiment.values["false-alarm"]
        num_of_emails = self.experiment.values["email-count"]
        print("=======================================================")
        print("Number of false alarms:", num_of_false_alarms)
        print("Number of emails:", num_of_emails)
        print("False alarm rate:", num_of_false_alarms / num_of_emails)
        print("=======================================================")
        print("Number of Detectable Emails:", self.experiment.values["valid-to-detect"])
        print("Number Detected:", self.experiment.values["detected"])
        print("Number Undetected:", self.experiment.values["valid-to-detect"] - self.experiment.values["detected"])
        print("Detection Rate:", self.experiment.values["detected"] / self.experiment.values["valid-to-detect"])

    def inconsistentUserDistributions(self):
        senders = self.getNamesToSenders()
        for s in senders:
            curr_sender = senders[s]
            curr_mailers = curr_sender.xmailer_distribution.keys()
            if len(curr_mailers) > 1:
                print("=========")
                print("Sender: ", s)
                print("Distribution:")
                for x in curr_sender.xmailer_distribution:
                    print(str(x) + ":", curr_sender.xmailer_distribution[x])
def randomEmailGenerator(mbox):
    name_lst = []
    xmailer_lst = []
    for msg in mbox:
        currName = extract_name(msg)
        currXmailer = getXMailer(msg)
        if currName != None:
            name_lst.append(currName)
        xmailer_lst.append(currXmailer)
    def randomEmailData():
        randomName = name_lst[random.randrange(len(name_lst))]
        randomXmailer = xmailer_lst[random.randrange(len(xmailer_lst))]
        return (randomName, randomXmailer)
    return randomEmailData

# def randomEmailData(mbox):
#     random_email_name = extract_name(mbox[random.randrange(len(mbox))])
#     while not random_email_name:
#         random_email_name = extract_name(mbox[random.randrange(len(mbox))])
#     random_email_xmailer = getXMailer(mbox[random.randrange(len(mbox))])
#     while not random_email_xmailer:
#         random_email_xmailer = getXMailer(mbox[random.randrange(len(mbox))])
#     return (random_email_name, random_email_xmailer)


def extractVersion(xmailer):
    r = re.compile("\d+(\.\d+)+")
    return r.sub("", xmailer)


def extractParentheticals(xmailer):
    pairings = [("\(", "\)"), ("\[", "\]"), ("\*", "\*"), ("<", ">"), ("\- ", ""), ("ver", ""), ("\(", ""), (" \d", "")]
    for left, right in pairings:
        exp = left + ".*" + right
        r = re.compile(exp)
        xmailer = r.sub("", xmailer)
    return xmailer


def removeSpaces(xmailer):
    exp = " +$"
    r = re.compile(exp)
    xmailer = r.sub("", xmailer)
    return xmailer


def getXMailer(msg):
    xmailer = msg["Content-Transfer-Encoding"]
    return xmailer


def getSimilar(given_str, given_set):
    for s in given_set:
        # if s and given_str and Levenshtein.ratio(given_str, s) > 0.9:
        if (not s and not given_str) or (s and given_str and given_str.lower() == s.lower()):
            return s
    return False


def extract_name(msg):
    from_header = msg["From"]
    if not from_header:
        return None
    from_header = from_header.lower()
    r = re.compile(" *<.*> *")
    from_header = r.sub("", from_header)
    r = re.compile("^ +")
    from_header = r.sub("", from_header)
    return from_header


file_name = "/Volumes/HP c310w/" + argv[1]
a = Analyzer(file_name)
a.runStatistics()
a.runExperiment()
# \d+(\.\d+)+
# extract everything in brackets, parenthesis, etc
# extract everything that looks like a version number
# cut off all first words as apart of similarity
# prefix matching in similarity
# perhaps try word COUNTING in similarity

# (), **, "- " "", [], <>, "ver" ""
# spaces
# version number
