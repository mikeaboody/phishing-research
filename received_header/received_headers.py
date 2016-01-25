from detector import Detector
import sys
import mailbox
import re
import pdb

class SenderReceiverPair:

	def __init__(self, sender, receiver):
		self.receiver = receiver
		self.sender = sender
		self.emailList = []


	def __str__(self):
		s = ""
		for email in self.emailList:
			s += str(email) + "\n"
		return s

class Email:

	count = 0
	def __init__(self):
		self.emailID = Email.count
		Email.count += 1
		self.receivedHeaderList = []

	def __str__(self):
		s = ""
		for rh in self.receivedHeaderList:
			s += str(rh) + " | "
		return s
		
class ReceivedHeader:

	def __init__(self, content):
		self.content = content
		self.analyze()
		
	def analyze(self):
		# self.SMTP_ID = None
		# self.SMTP_IP = None
		# self.date = None
		# self.SMTP_IP = self.extract_ip(content)

		#very simple breakdown scheme for receiver headers
		content = self.content
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
		
		#id: id
		#with: type of SMTP server
		#;: date
		#by is domain part of the message id's
		#from is the name server


	def extract_ip(self, content):
		r = re.search("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", content)
		return r.group()


	def __str__(self):
		return str(self.breakdown)
		# return "SMTP ID: " + str(self.SMTP_ID) + ", SMTP IP: " + str(self.SMTP_IP) + ", date: " + str(self.date)


class SenderReceiverProfile(dict):
	def __init__(self, inboxPath):
		self.inbox = mailbox.mbox(inboxPath)
		self.analyze()
		# self.writeReceivedHeadersToFile()

	def analyze(self):
		for msg in self.inbox:
			if "List-Unsubscribe" not in msg:
				self.appendEmail(msg)


	def appendEmail(self, msg):
		sender = extract_email(msg)
		receiver = myEmail
		if (sender, receiver) not in self:
			self[(sender, receiver)] = SenderReceiverPair(sender, receiver)
		srp = self[(sender, receiver)]
		newEmail = Email()
		if (msg.get_all("Received") != None):
			for receivedHeader in msg.get_all("Received"):
				rh = ReceivedHeader(receivedHeader)
				newEmail.receivedHeaderList.append(rh)
			srp.emailList.append(newEmail)

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


def extract_email(msg):
    from_header = msg["From"]
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

class receivedHeadersDetector(Detector):
	def __init__(self):
		self.srp = self.create_sender_profile()

	def modify_phish(self, phish, msg):
		pass

	def classify(self, phish):
		pass

	def create_sender_profile(self):
		srp = SenderReceiverProfile(file_name)
		return srp

	def find_false_positives(self):
		total_emails_flagged = 0
		total_srp_flagged = 0
		invalidEmails = 0 # if a received header for an email doesn't have the "by" field
		for tup, srp in self.srp.items():
			# {#: [[by1-1, by1-2], by2, .., by#], ...}
			by_sequences = {}
			flagSRP = False
			for em in srp.emailList:
				num_recHeaders = len(em.receivedHeaderList)
				flagEmail = False
				invEmail = False
				# Check that all received headers have a "by" field
				for recHeader in em.receivedHeaderList:
					if not "by" in recHeader.breakdown.keys():
						invEmail = True
				if invEmail:
					break

				# new length of received headers seen
				# Do not flag
				if not num_recHeaders in by_sequences.keys():
					store = em.receivedHeaderList[0].breakdown["by"]
					if re.search("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", store): # ip addr case
						store = store[0:store[store.index(".")+1:].index(".") + store.index(".") + 1]
					elif store.count(".") > 1 or len(store) > 15: # domain name case
						store = store.split(".")[-2] + "." + store.split(".")[-1]
					by_sequences[num_recHeaders] = [[store]]
					for rh in range(1,num_recHeaders):
						store = em.receivedHeaderList[rh].breakdown["by"]
						if re.search("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", store): # ip addr case
							store = store[0:store[store.index(".")+1:].index(".") + store.index(".") + 1]
						elif store.count(".") > 1: # domain name case
							store = store.split(".")[-2] + "." + store.split(".")[-1]
						by_sequences[num_recHeaders].append([store])
				else:
					# length of received headers seen before
					# flag if it doesn't match what has been seen before
					seenRecHeaders = by_sequences[num_recHeaders]

					for rh in range(num_recHeaders):
						store = em.receivedHeaderList[rh].breakdown["by"]
						if re.search("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", store): # ip addr case
							store = store[0:store[store.index(".")+1:].index(".") + store.index(".") + 1]
						elif store.count(".") > 1: # domain name case
							store = store.split(".")[-2] + "." + store.split(".")[-1]
						if not store in by_sequences[num_recHeaders][rh]:
							# pdb.set_trace()
							flagEmail = True
							flagSRP = True
							by_sequences[num_recHeaders][rh].append(store)
				if flagEmail:
					total_emails_flagged += 1
			if flagSRP:
				total_srp_flagged += 1
		print("Total Number of Emails Flagged: " + str(total_emails_flagged))
		print("Total Number of SRP's Flagged: " + str(total_srp_flagged))

	
	# Compares to see if ip1 and ip2 fall in same subnet /16
	# returns true if they are the same
	def compareIP16(self, ip1, ip2):
		if ip1.count(".") == 3 and ip2.count(".") == 3:
			prefix1 = ip1[0:ip1[ip1.index(".")+1:].index(".") + ip1.index(".") + 1]
			prefix2 = ip2[0:ip2[ip2.index(".")+1:].index(".") + ip2.index(".") + 1]
			return prefix1 == prefix2
		return False

file_name = "/home/apoorva/Documents/Research/PhishingResearch/Inbox.mbox"
myEmail = "nexusapoorvacus19@gmail.com"
detector = receivedHeadersDetector()
detector.find_false_positives()

# Results
# Total Number of Emails Flagged: 355/4514 <-- 0.0786 --> 7.86% False Positive Rate
# Total Number of SRP's Flagged: 157/505 <-- 0.311 --> 31.1% False Positive Rate