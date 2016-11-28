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

import logging
import os
import sys

import inbox
import numpy as np
import scipy.io as sio

import feature_classes as fc
import logs

progress_logger = logging.getLogger('spear_phishing.progress')

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
        if self.num_emails <= 1:
            self.sender_profile_num_emails = 0
            self.data_matrix_num_emails = 0
            self.test_matrix_num_emails = self.num_emails
        else:
            self.sender_profile_num_emails = int(np.ceil(self.sender_profile_percentage * self.num_emails))
            self.data_matrix_num_emails = int(np.ceil(self.data_matrix_percentage * self.num_emails))
            self.test_matrix_num_emails = self.num_emails - self.sender_profile_num_emails - self.data_matrix_num_emails


        self.start_sender_profile_index = 0
        self.start_data_matrix_index = self.start_sender_profile_index + self.sender_profile_num_emails
        self.start_test_matrix_index = self.start_data_matrix_index + self.data_matrix_num_emails


    def should_enable_extra_debugging(self, inbox, detectors):
        if len(inbox) < 10000:
            return False
        detector_names = ', '.join([type(d).__name__ for d in detectors])
        progress_logger.info('Enabling extra debugging for large inbox, {}; RSS = {}, creating sender profiles for {}'.format(logs.context, MemTracker.cur_mem_usage(), detector_names))
        return True

    def build_detectors(self, inbox):
        logs.context['step'] = 'build_detectors'
        detectors = [Detector(inbox) for Detector in self.features]
        verbose = self.should_enable_extra_debugging(inbox, detectors)
        for i, detector in enumerate(detectors):
            logs.context['detector'] = type(detector).__name__
            detector.create_sender_profile(self.sender_profile_num_emails)
            logs.Watchdog.reset()
            if verbose:
                progress_logger.info('Finished creating {} sender profile, RSS = {}'.format(type(detector).__name__, MemTracker.cur_mem_usage()))
                MemTracker.logMemory('finished creating {} sender profile'.format(type(detector).__name__))
            else:
                logs.RateLimitedMemTracker.checkmem('finished creating {} sender profile'.format(type(detector).__name__))
        del logs.context['step']
        del logs.context['detector']
        return detectors
    
    def generate_data_matrix(self, inbox, phish_inbox):
        logs.context['step'] = 'generate_data_matrix'
        data_matrix = np.empty(shape=(self.data_matrix_num_emails*2, self.num_features))
    
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
        logs.Watchdog.reset()
        for i in range(self.start_data_matrix_index, self.start_test_matrix_index):
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
        logs.Watchdog.reset()
        del logs.context['step']
        return data_matrix
    
    def generate_test_matrix(self, test_mbox):
        logs.context['step'] = 'generate_test_matrix'
        test_data_matrix = np.empty(shape=(self.num_emails - self.start_test_matrix_index, self.num_features))
    
        test_mess_id = np.empty(shape=(self.num_emails - self.start_test_matrix_index, 1), dtype='S200')
        
        row_index = 0
        for i in range(self.start_test_matrix_index, self.num_emails):
            j = 0
            test_mess_id[row_index] = test_mbox[i]["Message-ID"]
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
        test_email_index = np.arange(self.start_test_matrix_index, self.num_emails)
        logs.Watchdog.reset()
        del logs.context['step']
        return test_data_matrix, test_email_index, test_mess_id
    
    def generate_labels(self):
        label_matrix = np.empty(shape=(self.data_matrix_num_emails*2, 1))
    
        for i in range(2 * self.data_matrix_num_emails):
            label_matrix[i][0] = 0 if i < self.data_matrix_num_emails else 1
        return label_matrix
    
######################
# Script Starts Here #
######################

    def run(self):
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
            test_X, test_index, test_mess_id= self.generate_test_matrix(self.emails)
            test_dict = {}
            test_dict['test_data'] = test_X
            test_dict['feature_names'] = self.feature_names
            test_dict['email_index'] = test_index
            test_dict['message_id'] = test_mess_id

            test_path = os.path.join(self.output_directory, 'test.mat')
            sio.savemat(test_path, test_dict)
