#!/usr/bin/env python

""" 
generate_features.py: Script that reads in spear-phishing and legitimate emails
and converts each training example into a feature vector.

Requirements:
-Python 2.7
-numpy ('pip install numpy')
-scipy ('pip install scipy')
-editdistance ('pip install editdistance')

The output of your file will be two .mat files 'training.mat' and 'test.mat'.

'training.mat'
    -'training_data'
    -'training_labels'

'test.mat'
    -'test_data'
"""

import os
import sys
import time
import inbox

import numpy as np
import scipy.io as sio

import feature_classes as fc

############
# FEATURES #
############
"""
Define your features in feature_classes.py, and add the class name to the
features list below. Feature classes must inherit from the Detector class
defined in detector.py.
"""

class FeatureGenerator(object):
    def __init__(self,
                 output_directory,
                 filename,
                 phish_filename,
                 sender_profile_percentage,
                 data_matrix_percentage,
                 test_matrix_percentage,
                 features):

        self.output_directory = output_directory
        self.sender_profile_percentage = sender_profile_percentage
        self.data_matrix_percentage = data_matrix_percentage
        self.test_matrix_percentage = test_matrix_percentage
        self.do_generate_data_matrix = False
        self.do_generate_test_matrix = False

        self.detectors = None
        self.features = features
        self.num_features = sum([feature.NUM_HEURISTICS for feature in self.features])
        self.feature_names = [f.__name__ + "-" + str(i) for f in self.features for i in range(f.NUM_HEURISTICS)]

        self.emails = inbox.Inbox(filename)
        self.phish_emails = inbox.Inbox(phish_filename)
        self.num_emails = len(self.emails)

        #Convert from percentages to number of emails in each
        self.sender_profile_num_emails = int(self.sender_profile_percentage * self.num_emails)
        self.data_matrix_num_emails = int(self.data_matrix_percentage * self.num_emails)
        self.test_matrix_num_emails = int(self.test_matrix_percentage * self.num_emails)

        self.start_sender_profile_index = 0
        self.start_data_matrix_index = self.start_sender_profile_index + self.sender_profile_num_emails
        self.start_test_matrix_index = self.start_data_matrix_index + self.data_matrix_num_emails


    def build_detectors(self, inbox):
        detectors = [Detector(inbox) for Detector in self.features]
        print("Building sender profiles for each feature...")
        for i, detector in enumerate(detectors):
            detector.create_sender_profile(self.sender_profile_num_emails)
        print('')
        return detectors
    
    def generate_data_matrix(self, inbox, phish_inbox):
        data_matrix = np.empty(shape=(self.data_matrix_num_emails*2, self.num_features))
    
        print("Generating data matrix...")
        row_index = 0
        for i in range(self.start_data_matrix_index, self.start_test_matrix_index):
            j = 0
            for detector in self.detectors:
                heuristic = detector.classify(inbox[i])
                if type(heuristic) == list:
                    for h in heuristic:
                        data_matrix[row_index][j] = float(h)
                        j += 1
                else:
                    data_matrix[row_index][j] = float(heuristic) if heuristic else 0.0
                    j += 1
            row_index += 1
        for i in range(0, self.start_data_matrix_index):
            j = 0
            for detector in self.detectors:
                heuristic = detector.classify(phish_inbox[i])
                if type(heuristic) == list:
                    for h in heuristic:
                        data_matrix[row_index][j] = float(h)
                        j += 1
                else:
                    data_matrix[row_index][j] = float(heuristic) if heuristic else 0.0
                    j += 1
            row_index += 1
        return data_matrix
    
    def generate_test_matrix(self, test_mbox):
        test_data_matrix = np.empty(shape=(self.num_emails - self.start_test_matrix_index, self.num_features))

        print("Generating test data matrix...")
        row_index = 0
        for i in range(self.start_test_matrix_index, self.num_emails):
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
            row_index += 1
        print('')

        test_email_indx = np.arange(self.start_test_matrix_index, self.num_emails)
        return test_data_matrix, test_email_indx
    
    def generate_labels(self):
        label_matrix = np.empty(shape=(self.data_matrix_num_emails*2, 1))
    
        print("Generating label matrix...")
        for i in range(self.data_matrix_num_emails):
            label_matrix[i][0] = 0 if i < self.data_matrix_num_emails else 1
        print('')
        return label_matrix
    
######################
# Script Starts Here #
######################

    def run(self):
        start_time = time.time()
        self.detectors = self.build_detectors(self.emails)
        if self.do_generate_data_matrix:
            X = self.generate_data_matrix(self.emails, self.phish_emails)
            Y = self.generate_labels()
            training_dict = {}
            training_dict['training_data'] = X
            training_dict['training_labels'] = Y
            training_dict['feature_names'] = self.feature_names

            training_path = os.path.join(self.output_directory, 'training.mat')
            sio.savemat(training_path, training_dict)

        if self.do_generate_test_matrix:
            test_X, test_indx = self.generate_test_matrix(self.emails)
            test_dict = {}
            test_dict['test_data'] = test_X
            test_dict['email_index'] = test_indx
            test_dict['feature_names'] = self.feature_names

            test_path = os.path.join(self.output_directory, 'test.mat')
            sio.savemat(test_path, test_dict)
            
        end_time = time.time()
        
        print("The script took {} seconds.".format(int(end_time - start_time)))

