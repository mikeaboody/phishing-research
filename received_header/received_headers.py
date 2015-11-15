pairs = {}

class sender_receiver_pair:

	def __init__(self):
		self.receiver
		self.sender
		self.email_list


class email:

	def __init__(self):
		self.emailID
		self.received_header_list = []


class received_header:

	def __init__(self):
		self.SMTP_ID
		self.SMTP_IP
		self.date


# Need to iterate through emails and for each sender_receiver_pair we see, we create received_header objects for each received header. We create an email object for this particular email and save the received_header objects in the email's list. Lastly, we save the email in the sender_receiver_pair's email list.