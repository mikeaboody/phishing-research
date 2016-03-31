import os
from collections import defaultdict

class Inbox():
	def __init__(self, root):
		self.emails = []
		self.processEmails(root)
	def processEmails(self, root):
		for item in os.listdir(root):
			level1Dir = os.path.join(root, item)
			if os.path.isdir(level1Dir):
				for item in os.listdir(level1Dir):
					level2Dir = os.path.join(level1Dir, item)
					if os.path.isdir(level2Dir):
						for item in os.listdir(level2Dir):
							level3Dir = os.path.join(level2Dir, item)
							if os.path.isdir(level3Dir):
								for item in os.listdir(level3Dir):
									logFileName = os.path.join(level3Dir, item)
									if os.path.isfile(logFileName) and logFileName.endswith(".log"):
										#read log file
										with open(logFileName, "r") as logFile:
											for line in logFile:
												currEmailDict = eval(line)
												currEmailDict = defaultdict(lambda: None, currEmailDict)
												self.emails.append(currEmailDict)
	def __getitem__(self, key):
		return self.emails[key.upper()]
	def __setitem__(self, key, value):
		self.emails[key.upper()] = value
	def __len__(self):
		return len(self.emails)
	def __iter__(self):
		return iter(self.emails)
