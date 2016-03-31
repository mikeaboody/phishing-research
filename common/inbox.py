import os
from collections import defaultdict

class Inbox():
	def __init__(self, root):
		self.emails = []
		self.processEmails(root)
	def processEmails(self, root):
		for item in os.listdir(root):
			subDir = os.path.join(root, item)
			if os.path.isdir(subDir):
				self.processEmails(subDir)
			else:
				logFileName = os.path.join(root, item)
				if os.path.isfile(logFileName) and logFileName.endswith(".log"):
					with open(logFileName, "r") as logFile:
						for line in logFile:
							currEmailDict = eval(line)
							self.emails.append(Email(currEmailDict))										
	def __getitem__(self, key):
		return self.emails[key]
	def __setitem__(self, key, value):
		self.emails[key] = value
	def __len__(self):
		return len(self.emails)
	def __iter__(self):
		return iter(self.emails)
class Email():
	def __init__(self, emailDict):
		self.headers = defaultdict(lambda: None, emailDict)
	def __getitem__(self, key):
		return self.headers[key.upper()]
	def __setitem__(self, key, value):
		self.emails[key.upper()] = value
	def get_all(self, key):
		if type(self[key]) is list:
			return self[key]
		else:
			return [self[key]]


box = Inbox("output")
for msg in box:
	print(msg["From"])
	print(msg["X-Mailer"])
	print(msg.get_all("X-Mailer"))
import pdb; pdb.set_trace()
