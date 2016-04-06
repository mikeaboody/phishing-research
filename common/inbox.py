import os
from collections import defaultdict
from random import shuffle
import copy
import time
import email.utils

class Inbox():
	def __init__(self, root):
		self.emails = []
		self.num_invalid_emails = 0
		self.processEmails(root)
		self.sort_emails()
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
							try:
								header_tuples = eval(line)
								self.emails.append(Email(header_tuples))	
							except:
								print("INVALID EMAIL")
								self.num_invalid_emails += 1
																
	def __getitem__(self, key):
		return self.emails[key]
	def __setitem__(self, key, value):
		self.emails[key] = value
	def __len__(self):
		return len(self.emails)
	def __iter__(self):
		return iter(self.emails)
	def sort_emails(self):
		def compare_emails(email1, email2):
			date_header1 = email1["Date"]
			date_header2 = email2["Date"]
			if date_header1 == date_header2:
				return 0
			if not date_header1 or not email.utils.parsedate(date_header1):
				return 1
			if not date_header2 or not email.utils.parsedate(date_header2):
				return -1
			time1 = time.mktime(email.utils.parsedate(date_header1))
			time2 = time.mktime(email.utils.parsedate(date_header2))
			if time1 == time2:
				return 0
			if time1 < time2:
				return -1
			return 1
		self.emails = sorted(self.emails, cmp=compare_emails)

class Email():
	def __init__(self, headers_arg=None):
		if not headers_arg:
			self.header_dict = {}
			self.ordered_headers = []
		else:
			self.header_dict = {}
			self.ordered_headers = []
			for key, value in headers_arg:
				self.header_dict[key.upper()] = value
				self.ordered_headers.append(key.upper())
	def __getitem__(self, key):
		if key.upper() not in self.header_dict:
			return None
		return self.header_dict[key.upper()]
	def __setitem__(self, key, value):
		if key.upper() not in self.header_dict:
			self.ordered_headers.append(key.upper())
		self.header_dict[key.upper()] = value
	def __len__(self):
		return len(self.ordered_headers)
	def __iter__(self):
		return iter(self.ordered_headers)
	def get_all(self, key):
		if type(self.header_dict[key.upper()]) is list:
			return self.header_dict[key.upper()]
		else:
			return [self.header_dict[key.upper()]]
	def keys(self):
		return self.ordered_headers
	def values(self):
		res = []
		for key in self.ordered_headers:
			res.append(self.header_dict[key])
		return res
	def items(self):
		res = []
		for key in self.ordered_headers:
			res.append((key, self.header_dict[key]))
		return res
