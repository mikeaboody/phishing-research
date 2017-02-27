class ResultRecord:
    def __init__(self, path, email_index, prob_phish, test_index, detector_contribution, email):
	self.path = path
        self.email_index = email_index
	self.probability_phish = prob_phish
	self.test_index = test_index
	self.detector_contribution = detector_contribution.items()
	self.email = email
	from_header = ""
	if "FROM" in self.email:
	    from_header = self.email["FROM"]
	self.email_from = from_header
	subject = ""
	if "SUBJECT" in self.email:
	    subject = self.email["SUBJECT"]
	self.email_subject = subject
	mess_id = ""
	if "MESSAGE-ID" in self.email:
	    mess_id = self.email["MESSAGE-ID"]
	self.email_message_id = mess_id

    def __str__(self):
        return str(self.email.header_dict)

    def __repr__(self):
        return str(self.email.header_dict)
