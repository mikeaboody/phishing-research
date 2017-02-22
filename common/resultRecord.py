import numpy as np

class ResultRecord:
    def __init__(self, path, email_index, prob_phish, test_index, mess_id, detector_contribution, all_headers):
	self.path = path
        self.email_index = email_index
	self.probability_phish = prob_phish
	self.test_index = test_index
	self.message_id = mess_id
	self.detector_contribution = detector_contribution.items()
	self.all_headers = all_headers
	self.email_from = self.all_headers["FROM"]
	subject = ""
	if "SUBJECT" in self.all_headers:
	    subject = self.all_headers["SUBJECT"]
	self.email_subject = subject

    # functionality moved to classify.py	
    # returns a list of Result Record objects given a path and indx
    def createRecords(test_X, indx, path, test_indx, test_mess_id):
	sample_size = test_X.shape[0]
	if sample_size == 0:
	    return []
	
	path = os.path.join(path, "legit_emails.log")
	prob_phish = self.clf.predict_proba(test_X)[:,1].reshape(sample_size,1)
	prob_phish[prob_phish < float(0.0001)] = 0
        
	records = []
	for i in range(sample_size):
	    detector_contribution = get_detector_contribution(test_X, test_indx[i])
	    records.append(ResultRecord(path, indx[i], prob_phish[i], test_indx[i], test_mess_id[i], detector_contribution, eval(get_email(path, indx[i]))))
	return records
    # functionality moved to classify.py
    def get_detector_contribution(test_X, test_indx):
        # Removing the ending "legit_emails.log" and adding "test.mat"
        test_sample = test_X['test_data'][test_indx]
        # get column averages
        col_averages = np.mean(test_X['test_data'], axis=0).reshape((self.num_features,1))
        test_sample_minus_mean = test_sample.reshape((self.num_features, 1)) - col_averages
        product = np.multiply(test_sample_minus_mean.reshape(self.num_features), self.clf_coef)
        d_contribution = {}
        curr = None
        for i, d in enumerate(self.d_name_per_feat):
            if curr is None or d != curr:
                curr = d
                d_contribution[curr] = 0
            d_contribution[curr] += product[i]
        return OrderedDict(sorted(d_contribution.items(), key=lambda t: t[1], reverse=True))
    
    # fuctionality moved to classify.py
    def get_email(path, email_index):
	with open(path) as fp:
	    for i, line in enumerate(fp):
	        if i == email_index:
		    return line

    def __str__(self):
        return str(self.all_headers)

    def __repr__(self):
        return str(self.all_headers)
