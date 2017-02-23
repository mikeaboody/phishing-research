import os
from collections import defaultdict
from random import shuffle
import copy
import time
import email.utils
import logging
import logs

class Inbox():
	def __init__(self, root=None):
		self.emails = []
		self.num_invalid_emails = 0
		if root != None:
			self.processEmails(root)
			self.sort_emails()
	def processEmails(self, root):
		if os.path.isfile(root) and root.endswith(".log"):
			logFileName = root
			with open(logFileName, "r") as logFile:
				i = 0
				for line in logFile:
					try:
						header_tuples = eval(line)
						self.emails.append(Email(i, header_tuples))
					except:
                                                logs.RateLimitedLog("Invalid Email, during processEmails()", private=line)
						self.num_invalid_emails += 1
					i += 1
		elif os.path.isdir(root):
			for item in os.listdir(root):
				subDir = os.path.join(root, item)
				self.processEmails(subDir)
																
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
			time1 = email1.get_time()
			time2 = email2.get_time()
			if time1 == time2:
				return 0
			if time1 == None:
				return 1
			if time2 == None:
				return -1
			if time1 < time2:
				return -1
			return 1

		self.emails = sorted(self.emails, cmp=compare_emails)

class Email():
	def __init__(self, file_index=-1, headers_arg=None):
		self.file_index = file_index
		self.header_dict = {}
		self.ordered_headers = []
		if headers_arg != None:
			for key, value in headers_arg:
					values = self.get_all(key.upper())[:]
					values.append(value)
					self.header_dict[key.upper()] = values
					self.ordered_headers.append(key.upper())

	def __getitem__(self, key):
		if key.upper() not in self.header_dict:
			return None
		return self.get_all(key.upper())[0]
	def __setitem__(self, key, value):
		if key.upper() not in self.header_dict:
			self.header_dict[key.upper()] = []
		self.header_dict[key.upper()].append(value)
		self.ordered_headers.append(key.upper())
	def __len__(self):
		return len(self.ordered_headers)
	def __iter__(self):
		return iter(self.ordered_headers)
	def get_all(self, key):
		if key.upper() not in self.header_dict:
			return []
		return self.header_dict[key.upper()]
	def get_time(self):
		date_header = self["Date"]
		if not date_header:
			return None
		parsed_date = email.utils.parsedate(date_header)
		if not parsed_date:
			return None
		try:
			email_time = time.mktime(parsed_date)
			return email_time
		except ValueError:
			return None
		except OverflowError:
			return None

	def keys(self):
		return self.ordered_headers
	def values(self):
		raise NotImplementedError
	def items(self):
		raise NotImplementedError
