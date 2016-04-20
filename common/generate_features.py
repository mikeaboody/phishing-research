#!/usr/bin/env python

""" 
generate_features.py: Script that reads in spear-phishing and legitimate emails
and converts each training example into a feature vector.

Requirements:
-Python 2.7
-numpy ('pip install numpy')
-scipy ('pip install scipy')
-editdistance ('pip install editdistance')

The output of your file will be a .mat file. The data will be accessible using
the following keys:
    -'training_data'
    -'training_labels'
    -'test_data'
    -'test_labels'
"""

import os
import sys
import time
import inbox

import numpy as np
import scipy.io as sio

import feature_classes as fc
from lookup import Lookup

PHISHING_FILENAME = 'phish'
REGULAR_FILENAME = 'regular'
TEST_FILENAME = 'test'
NUM_DATA = 2000

############
# FEATURES #
############
"""
Define your features in feature_classes.py, and add the class name to the
features list below. Feature classes must inherit from the Detector class
defined in detector.py.
"""

features = [
    fc.DateFormatDetector,
    fc.DateTimezoneDetector,
    fc.MessageIdDetectorOne,
    fc.messageIDDomain_Detector,
    fc.ContentTypeDetector,
    fc.OrderOfHeaderDetector,
    fc.XMailerDetector,
    fc.ReceivedHeadersDetector
]

class FeatureGenerator(object):
    def __init__(self):
        self.phishing_filename = PHISHING_FILENAME
        self.regular_filename = REGULAR_FILENAME
        self.test_filename = TEST_FILENAME

        #Get rid of this
        self.num_data = NUM_DATA
        self.num_pre_training = 0
        #In favor of this
        self.sender_profile_size = 0
        self.data_matrix_size = 0
        self.test_matrix_size = 0
        self.do_generate_data_matrix = False
        self.do_generate_test_matrix = False

        self.features = features
        
        self.detectors = None
        self.num_features = sum([feature.NUM_HEURISTICS for feature in self.features])
        self.feature_names = [f.__name__ + "-" + str(i) for f in self.features for i in range(f.NUM_HEURISTICS)]

    def progress_bar(self, index, last_val, num_bars=20, msg='Progress'):
        percent = (float(index) + 1) / last_val
        hashes = '#' * int(round(percent * num_bars))
        spaces = ' ' * (num_bars - len(hashes))
        sys.stdout.write("\r{0}: [{1}] {2}%".format(msg, hashes + spaces, int(round(percent * 100))))
        sys.stdout.flush()
    
    def build_detectors(self, regular_mbox):
        detectors = [Detector(regular_mbox) for Detector in self.features]
        print("Building sender profiles for each feature...")
        for i, detector in enumerate(detectors):
            detector.create_sender_profile(self.num_pre_training)
            self.progress_bar(i, len(detectors))
        print('')
        return detectors
    
    # Generates a single pseudo-phishing email.
    def make_phish(self, test_mbox):
        sender = None
        random_msg = None
        random_from = None
        # Want to make sure we've seen sender before.
        while not sender or sender not in self.detectors[0].sender_profile:
            i, j = np.random.randint(0, len(test_mbox)), np.random.randint(0, len(test_mbox))
            random_msg = test_mbox[i]
            random_from = test_mbox[j]
            sender = random_from['From']
    
        phish = inbox.Email()
        for key in random_msg.keys():
            phish[key] = random_msg[key]
        phish['From'] = sender
        return phish
    
    def generate_data_matrix(self, phishing_mbox, regular_mbox):
        assert len(regular_mbox) > self.num_pre_training, "Not enough data points."
        data_matrix = np.empty(shape=(NUM_DATA, self.num_features))
    
        print("Generating data matrix...")
        row_index = 0
        for i in range(self.num_pre_training, len(regular_mbox)):
            j = 0
            for detector in self.detectors:
                heuristic = detector.classify(regular_mbox[i])
                if type(heuristic) == list:
                    for h in heuristic:
                        data_matrix[row_index][j] = float(h)
                        j += 1
                else:
                    data_matrix[row_index][j] = float(heuristic) if heuristic else 0.0
                    j += 1
            if row_index % 10 == 0:
                self.progress_bar(row_index, NUM_DATA)
            row_index += 1
        for _ in range(NUM_DATA / 2):
            phish_email = phishing_mbox[i] if phishing_mbox else self.make_phish(regular_mbox)
            j = 0
            for detector in self.detectors:
                heuristic = detector.classify(phish_email)
                if type(heuristic) == list:
                    for h in heuristic:
                        data_matrix[row_index][j] = float(h)
                        j += 1
                else:
                    data_matrix[row_index][j] = float(heuristic) if heuristic else 0.0
                    j += 1
            if row_index % 10 == 0:
                self.progress_bar(row_index, NUM_DATA)
            row_index += 1
        print('')
        return data_matrix
    
    def generate_test_matrix(self, test_mbox):
        num_test_points = len(test_mbox)
        test_data_matrix = np.empty(shape=(2 * num_test_points, self.num_features))
    
        print("Generating test data matrix...")
        row_index = 0
        for i in range(num_test_points):
            j = 0
            for detector in self.detectors:
                heuristic = detector.classify(test_mbox[i])
                if type(heuristic) == list:
                    for h in heuristic:
                        test_data_matrix[row_index][j] = float(h)
                        j += 1
                else:
                    test_data_matrix[row_index][j] = float(heuristic) if heuristic else 0.0
                    j += 1
            if row_index % 10 == 0:
                self.progress_bar(row_index, 2 * num_test_points)
            row_index += 1
        for _ in range(num_test_points):
            phish_email = self.make_phish(test_mbox)
            j = 0
            for detector in self.detectors:
                heuristic = detector.classify(phish_email)
                if type(heuristic) == list:
                    for h in heuristic:
                        test_data_matrix[row_index][j] = float(h)
                        j += 1
                else:
                    test_data_matrix[row_index][j] = float(heuristic) if heuristic else 0.0
                    j += 1
            if row_index % 10 == 0:
                self.progress_bar(row_index, 2 * num_test_points)
            row_index += 1
        print('')
        return test_data_matrix
    
    def generate_labels(self, phishing_mbox, regular_mbox):
        assert len(regular_mbox) > self.num_pre_training, "Not enough data points."
        label_matrix = np.empty(shape=(NUM_DATA, 1))
    
        print("Generating label matrix...")
        for i in range(NUM_DATA):
            label_matrix[i][0] = 0 if i < NUM_DATA / 2 else 1
            if i % 10 == 0:
                self.progress_bar(i, NUM_DATA)
        print('')
        return label_matrix
    
    def generate_test_labels(self, test_mbox):
        num_test_points = len(test_mbox)
        test_label_matrix = np.empty(shape=(2 * num_test_points, 1))
    
        print("Generating test label matrix...")
        for i in range(2 * num_test_points):
            test_label_matrix[i][0] = 0 if i < num_test_points else 1
            if i % 10 == 0:
                self.progress_bar(i, 2 * num_test_points)
        print('')
        return test_label_matrix


######################
# Script Starts Here #
######################

    def run(self):
        start_time = time.time()
        if os.path.exists(self.phishing_filename):
            phishing_emails = inbox.Inbox(self.phishing_filename)
        else:
            print("No phishing emails provided.")
            phishing_emails = None
        regular_emails = inbox.Inbox(self.regular_filename)
        test_emails = inbox.Inbox(self.test_filename)
        self.num_pre_training = len(regular_emails) - self.num_data / 2
        Lookup.loadAll()
        self.detectors = self.build_detectors(regular_emails)
        X = self.generate_data_matrix(phishing_emails, regular_emails)
        Y = self.generate_labels(phishing_emails, regular_emails)
        test_X = self.generate_test_matrix(test_emails)
        test_Y = self.generate_test_labels(test_emails)

        file_dict = {}
        file_dict['training_data'] = X
        file_dict['training_labels'] = Y
        file_dict['test_data'] = test_X
        file_dict['test_labels'] = test_Y
        file_dict['feature_names'] = self.feature_names
        sio.savemat('phishing_data.mat', file_dict)
        end_time = time.time()
        
        print("Data matrix has been generated. There are {} total training points and {} total features.".format(len(X), len(X[0])))
        print("Test matrix has been generated. There are {} total test points and {} total features.".format(len(test_X), len(test_X[0])))
        print("The script took {} seconds.".format(int(end_time - start_time)))

if __name__ == '__main__':
    feature_generator = FeatureGenerator()
    feature_generator.run()
