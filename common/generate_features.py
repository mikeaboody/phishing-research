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

import logs
from memtest import MemTracker
import time

progress_logger = logging.getLogger('spear_phishing.progress')
debug_logger = logging.getLogger('spear_phishing.debug')

class FeatureGenerator(object):
    def __init__(self,
                 output_directory,
                 filename,
                 phish_filename,
                 sender_profile_percentage,
                 data_matrix_percentage,
                 test_matrix_percentage,
                 sender_profile_time_interval,
                 train_time_interval,
                 test_time_interval,
                 use_percentages,
                 features):

        self.output_directory = output_directory
        self.sender_profile_percentage = sender_profile_percentage
        self.data_matrix_percentage = data_matrix_percentage
        self.test_matrix_percentage = test_matrix_percentage
        self.sender_profile_time_interval = sender_profile_time_interval
        self.train_time_interval = train_time_interval
        self.test_time_interval = test_time_interval
        self.use_percentages = use_percentages

        self.do_generate_data_matrix = False
        self.do_generate_test_matrix = False

        self.detectors = None
        self.features = features
        self.num_features = sum([feature.NUM_HEURISTICS for feature in self.features])
        self.feature_names = [f.__name__ + "-" + str(i) for f in self.features for i in range(f.NUM_HEURISTICS)]

        self.emails = inbox.Inbox(filename)
        self.phish_emails = inbox.Inbox(phish_filename)
        self.num_emails = len(self.emails)

        if self.use_percentages:

            #Convert from percentages to number of emails in each
            if self.num_emails <= 1:
                self.sender_profile_num_emails = 0
                self.data_matrix_num_emails = 0
                self.test_matrix_num_emails = self.num_emails
            else:
                self.sender_profile_num_emails = int(np.ceil(self.sender_profile_percentage * self.num_emails))
                self.data_matrix_num_emails = int(np.ceil(self.data_matrix_percentage * self.num_emails))
                self.test_matrix_num_emails = self.num_emails - self.sender_profile_num_emails - self.data_matrix_num_emails


            start_sender_profile_index = 0
            start_data_matrix_index = start_sender_profile_index + self.sender_profile_num_emails
            start_test_matrix_index = start_data_matrix_index + self.data_matrix_num_emails

            self.sender_profile_indeces = range(start_sender_profile_index, start_data_matrix_index)

            self.data_matrix_indeces = range(start_data_matrix_index, start_test_matrix_index)
            self.test_matrix_indeces = range(start_test_matrix_index, self.num_emails)

            self.data_matrix_num_phish_emails = self.data_matrix_num_emails
            self.data_matrix_phish_indeces = range(start_data_matrix_index, start_test_matrix_index)

        else:
            index_intervals = self.split_legit_emails_by_time(self.emails, sender_profile_time_interval, self.train_time_interval, self.test_time_interval)
            self.sender_profile_indeces, self.data_matrix_indeces, self.test_matrix_indeces = index_intervals
            self.data_matrix_phish_indeces = self.split_phish_emails_by_time(self.phish_emails, self.train_time_interval)

            self.sender_profile_num_emails = len(self.sender_profile_indeces)
            self.data_matrix_num_emails = len(self.data_matrix_indeces)
            self.test_matrix_num_emails = len(self.test_matrix_indeces)
            self.data_matrix_num_phish_emails = len(self.data_matrix_phish_indeces)

    def split_legit_emails_by_time(self, legit_inbox, sender_profile_time_interval, train_time_interval, test_time_interval):
        """ Returns 3 sets of indeces corresponding to legit emails that go into the sender profile,
            the data matrix, and the test matrix based on their given time intervals"""
        sender_profile_start_time = sender_profile_time_interval[0]
        sender_profile_end_time = sender_profile_time_interval[1]
        train_start_time = train_time_interval[0]
        train_end_time = train_time_interval[1]
        test_start_time = test_time_interval[0]
        test_end_time = test_time_interval[1]

        sender_profile_indeces = []
        train_indeces = []
        test_indeces = []

        for i in range(len(legit_inbox)):
            email = legit_inbox[i]
            email_time = email.get_time()

            if email_time != None and email_time >= sender_profile_start_time and email_time < sender_profile_end_time:
                sender_profile_indeces.append(i)
            elif email_time != None and email_time >= train_start_time and email_time < train_end_time:
                train_indeces.append(i)
            elif email_time == None or (email_time >= test_start_time and email_time < test_end_time):
                test_indeces.append(i)

        return sender_profile_indeces, train_indeces, test_indeces

    def split_phish_emails_by_time(self, phish_inbox, train_time_interval):
        """ Returns 1 set of indeces corresponding to phishing emails that go into the data matrix
            based on their given time intervals """
        train_start_time = train_time_interval[0]
        train_end_time = train_time_interval[1]
        train_indeces = []

        for i in range(len(phish_inbox)):
            email = phish_inbox[i]
            email_time = email.get_time()
            if email_time != None and email_time >= train_start_time and email_time < train_end_time:
                train_indeces.append(i)
        return train_indeces



    def should_enable_extra_debugging(self, inbox, detectors):
        if len(inbox) < 10000:
            return False
        detector_names = ', '.join([type(d).__name__ for d in detectors])
        progress_logger.info('Enabling extra debugging for large inbox with {} messages, {}; RSS = {}, creating sender profiles for {}'.format(len(inbox), logs.context, MemTracker.cur_mem_usage(), detector_names))
        return True

    def build_detectors(self, inbox):
        logs.context['step'] = 'build_detectors'
        detectors = [Detector(inbox) for Detector in self.features]
        verbose = self.should_enable_extra_debugging(inbox, detectors)
        for i, detector in enumerate(detectors):
            logs.context['detector'] = type(detector).__name__
            detector.create_sender_profile(self.sender_profile_indeces)
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
        data_matrix = np.zeros(shape=(self.data_matrix_num_emails + self.data_matrix_num_phish_emails, self.num_features), dtype='float64')
    
        legit_row = 0
        phish_row = self.data_matrix_num_emails
        for i in self.data_matrix_indeces:
            j = 0
            for detector in self.detectors:
                heuristic = detector.classify(inbox[i])
                if type(heuristic) == list:
                    for h in heuristic:
                        data_matrix[legit_row][j] = float(h)
                        j += 1
                else:
                    data_matrix[legit_row][j] = float(heuristic) if heuristic else 0.0
                    j += 1
            legit_row += 1
        for i in self.data_matrix_phish_indeces:
            j = 0
            for detector in self.detectors:
                heuristic = detector.classify(phish_inbox[i])
                if type(heuristic) == list:
                    for h in heuristic:
                        data_matrix[phish_row][j] = float(h)
                        j += 1
                else:
                    data_matrix[phish_row][j] = float(heuristic) if heuristic else 0.0
                    j += 1
            phish_row += 1
            for detector in self.detectors:
                detector.update_sender_profile(inbox[i])
        assert legit_row == self.data_matrix_num_emails
        assert phish_row == self.data_matrix_num_emails + self.data_matrix_num_phish_emails
        logs.Watchdog.reset()
        del logs.context['step']
        return data_matrix
    
    def generate_test_matrix(self, test_mbox):
        logs.context['step'] = 'generate_test_matrix'
        test_data_matrix = np.zeros(shape=(self.test_matrix_num_emails, self.num_features), dtype='float64')
    
        test_mess_id = np.zeros(shape=(self.test_matrix_num_emails, 1), dtype='S200')
        test_email_index = np.zeros(shape=(self.test_matrix_num_emails, 1), dtype="int32")
        row_index = 0
        for i in self.test_matrix_indeces:
            j = 0
            if test_mbox[i]["Message-ID"] == None:
                # logs.RateLimitedLog.log("Message-ID in test matrix is None.")
                test_mess_id[row_index] = "None"
            else:
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
            test_email_index[row_index] = test_mbox[i].file_index
            row_index += 1
            for detector in self.detectors:
                detector.update_sender_profile(test_mbox[i])
        # test_email_index = np.arange(self.start_test_matrix_index, self.num_emails)
        logs.Watchdog.reset()
        del logs.context['step']
        return test_data_matrix, test_email_index, test_mess_id
    
    def generate_labels(self):
        data_matrix_total_num_emails = self.data_matrix_num_emails + self.data_matrix_num_phish_emails
        label_matrix = np.zeros(shape=(data_matrix_total_num_emails, 1), dtype='float64')
    
        for i in range(self.data_matrix_num_emails):
            label_matrix[i][0] = 0
        for i in range(self.data_matrix_num_emails, data_matrix_total_num_emails):
            label_matrix[i][0] = 1
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

            if test_mess_id.shape[0] != test_X.shape[0]:
                progress_logger.info("BUG: test.map shapes don't match: {} vs {}, at {}".format(test_mess_id.shape, test_X.shape, logs.context))

            test_path = os.path.join(self.output_directory, 'test.mat')
            sio.savemat(test_path, test_dict)
