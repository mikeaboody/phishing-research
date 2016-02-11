from detector import Detector
import sys
import mailbox
import re
import pdb
import whois
from ipwhois import IPWhois
from netaddr import IPNetwork, IPAddress
import socket

class SenderReceiverPair:

	def __init__(self, sender, receiver):
		self.receiver = receiver
		self.sender = sender
		self.emailList = []
		self.public_ips = set()
		self.private_ips = set()
		self.public_domains = set()
		self.private_domains = set()


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
	privateCIDR = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
	seen_pairings = {}
	def __init__(self):
		self.srp = self.create_sender_profile()

	def modify_phish(self, phish, msg):
		msgHeaders = msg.get_all("Received")[:]
		del phish["Received"]
		for i in range(len(msgHeaders)):
			phish["Received"] = msgHeaders[i]
		return phish

	def classify(self, phish):
		pass

	def create_sender_profile(self):
		srp = SenderReceiverProfile(file_name)
		return srp

	# returns cidr of public IP or returns false if there is no IP or if the IP is private
	def public_IP(self, fromHeader):
		ip = extract_ip(fromHeader)
		if ip and not (IPAddress(ip) in IPNetwork(self.privateCIDR[0]) or IPAddress(ip) in IPNetwork(self.privateCIDR[1]) or IPAddress(ip) in IPNetwork(self.privateCIDR[2])):
			return ip
		return None


	def get_endMessageIDDomain(self, domain):
		if domain == None:
			return domain
		if '.' in domain:
			indexLastDot = len(domain) - domain[::-1].index(".") - 1
			rest = domain[:indexLastDot]
			if '.' in rest:
				indexNextDot = len(rest) - rest[::-1].index(".") - 1
				return domain[indexNextDot+1:]
		return domain

	# returns false if domain is invalid or private domain
	def public_domain(self, fromHeader):
		domain = extract_domain(fromHeader)
		if domain:
			domain = self.get_endMessageIDDomain(domain)
			try:
				return socket.gethostbyname(domain)
			except:
				return False

	def find_false_positives(self):
		total_num_emails = 0
		total_num_SRP = 0
		total_num_RH = 0
		total_emails_flagged = 0
		total_srp_flagged = 0
		invalidEmails = 0 # if a received header for an email doesn't have the "by" field
		numRHwoFrom = 0
		priv_ip = 0
		priv_dom = 0
		pub_ip = 0
		pub_dom = 0
		fp_from = open("falsePostives_from_2", "a")
		for tup, srp in self.srp.items():
			flagSRP = False
			seq_rh_from = []
			total_num_SRP += 1
			firstEmail = True
			for em in srp.emailList:
				# import pdb; pdb.set_trace()
				total_num_emails += 1
				num_recHeaders = len(em.receivedHeaderList)
				flagEmail = False
				invEmail = False
				RHList = []
				for recHeader in em.receivedHeaderList:
					if not "from" in recHeader.breakdown.keys():
						numRHwoFrom += 1
						RHList.append("None")
						continue
					elif self.public_IP(recHeader.breakdown["from"]):
						ip = self.public_IP(recHeader.breakdown["from"])
					elif self.public_domain(recHeader.breakdown["from"]):
						ip = self.public_domain(recHeader.breakdown["from"])
					else:
						# RHList.append("InvalidFrom")
						RHList.append("Invalid")
						continue
					try:
						# import pdb; pdb.set_trace()
						if ip in self.seen_pairings.keys():
							RHList.append(self.seen_pairings[ip])
						else:
							obj = IPWhois(ip)
							results = obj.lookup()
							if "nets" not in results.keys() or "cidr" not in results["nets"][0].keys():
								cidr = ip + "/32"
							else:
								cidr = results["nets"][0]["cidr"]
							RHList.append(cidr)
							self.seen_pairings[ip] = cidr
					except:
						# RHList.append("InvalidIPWhoIs")
						RHList.append("Invalid")
						self.seen_pairings[ip] = "Invalid"

				if RHList not in seq_rh_from:
					if seq_rh_from:
						fp_from.write(str(tup) + " " + str(RHList) + " " + str(seq_rh_from) + "\n")
						print(tup)
						flagEmail = True
						flagSRP = True
					seq_rh_from.append(RHList)


				if flagEmail:
					total_emails_flagged += 1
			if flagSRP:
				total_srp_flagged += 1

		print("Total number of RH w/o from: " + str(numRHwoFrom) + "/" + str(total_num_RH))
		print("Total Number of Emails Flagged: " + str(total_emails_flagged) + "/" + str(total_num_emails))
		print("Total Number of SRP's Flagged: " + str(total_srp_flagged) + "/" + str(total_num_SRP))

	
	# Compares to see if ip1 and ip2 fall in same subnet /16
	# returns true if they are the same
	def compareIP16(self, ip1, ip2):
		if ip1.count(".") == 3 and ip2.count(".") == 3:
			prefix1 = ip1[0:ip1[ip1.index(".")+1:].index(".") + ip1.index(".") + 1]
			prefix2 = ip2[0:ip2[ip2.index(".")+1:].index(".") + ip2.index(".") + 1]
			return prefix1 == prefix2
		return False

def extract_ip(content):
	r = re.search("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", content)
	return r.group() if r else None

def extract_domain(content):
	if ("(" in content):
		firstParen = content.index("(")
	else:
		return None
	return content[:firstParen-1]

file_name = sys.argv[1]
myEmail = sys.argv[2]
detector = receivedHeadersDetector()
detector.find_false_positives()

# Results
# Total Number of Emails Flagged: 355/4514 <-- 0.0786 --> 7.86% False Positive Rate
# Total Number of SRP's Flagged: 157/505 <-- 0.311 --> 31.1% False Positive Rate