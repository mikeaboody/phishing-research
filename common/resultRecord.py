class ResultRecord:
    def __init__(self, path, email_index, prob_phish, test_index, mess_id, detector_contribution, all_headers):
	self.path = path
        self.email_index = email_index
	self.probability_phish = prob_phish
	self.test_index = test_index
	self.message_id = mess_id
	self.detector_contribution = detector_contribution.items()
	self.all_headers = all_headers
	from_header = ""
	if "FROM" in self.all_headers:
	    from_header = self.all_headers["FROM"]
	self.email_from = from_header
	subject = ""
	if "SUBJECT" in self.all_headers:
	    subject = self.all_headers["SUBJECT"]
	self.email_subject = subject

    def __str__(self):
        return str(self.all_headers)

    def __repr__(self):
        return str(self.all_headers)
