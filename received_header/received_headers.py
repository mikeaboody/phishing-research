import sys
import mailbox
import re

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
		
FILE = open("receivedHeaders", "a")
class ReceivedHeader:

	def __init__(self, content):
		self.content = content
		# self.FILE = open("receivedHeaders", "a")
		self.analyze(content)
		# self.FILE.write("------------------------------------------------------\n")
		# self.FILE.close()
		
	def analyze(self, content):
		# self.SMTP_ID = None
		# self.SMTP_IP = None
		# self.date = None
		# self.SMTP_IP = self.extract_ip(content)

		#very simple breakdown scheme for receiver headers
		content_split = content.split("\n")
		content = ""
		for s in content_split:
			content += s
		content_split = content.split("\r")
		content = ""
		for s in content_split:
			content += s
		self.breakdown = {}
		possible_fields = ["from", "by", "via", "with", "id", "for", ";", "$"]
		for i in range(len(possible_fields)):
			start = possible_fields[i]
			for j in range(i+1, len(possible_fields)):
				end = possible_fields[j]
				r = re.search(start + "(.*)" + end, content)
				if r:
					match = r.group(1)
					self.breakdown[start] = match
					break
		# import pdb; pdb.set_trace()
		FILE.write(str(self.breakdown) + "\n")

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

	def analyze(self):
		for msg in self.inbox:
			if "List-Unsubscribe" not in msg:
				self.appendEmail(msg)


	def appendEmail(self, msg):
		sender = extract_email(msg)
		receiver = "nexusapoorvacus19@gmail.com"
		if (sender, receiver) not in self:
			self[(sender, receiver)] = SenderReceiverPair(sender, receiver)
		srp = self[(sender, receiver)]
		newEmail = Email()
		if (msg.get_all("Received") != None):
			for receivedHeader in msg.get_all("Received"):
				rh = ReceivedHeader(receivedHeader)
				newEmail.receivedHeaderList.append(rh)
			FILE.write("------------------------------------------------------\n")
			srp.emailList.append(newEmail)


def extract_email(msg):
    from_header = msg["From"]
    if not from_header:
        return None
    from_header = from_header.lower()
    r = re.search("([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)", from_header)
    return r.group() if r else from_header

srp = SenderReceiverProfile(sys.argv[1])
# Need to iterate through emails and for each sender_receiver_pair we see, we create received_header objects for each received header. We create an email object for this particular email and save the received_header objects in the email's list. Lastly, we save the email in the sender_receiver_pair's email list.