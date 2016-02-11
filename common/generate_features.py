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

import mailbox
import os
import sys
import time

import numpy as np
import scipy.io as sio

import feature_classes as fc

PHISHING_FILENAME = 'phish.mbox'
REGULAR_FILENAME = 'regular.mbox'
# REGULAR_FILENAME = 'Inbox.mbox'
TEST_FILENAME = 'test.mbox'
# Using 'matthew_berkeley.mbox'
NUM_DATA = 1000

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
    # fc.messageIDDomain_Detector,
    fc.ContentTypeDetector,
    fc.OrderOfHeaderDetector,
    fc.XMailerDetector
]

def build_detectors(regular_mbox):
    detectors = [Detector(regular_mbox) for Detector in features]
    print("Building sender profiles for each feature...")
    for detector in detectors:
        detector.create_sender_profile(NUM_PRE_TRAINING)
    return detectors

# Generates a single pseudo-phishing email.
def make_phish(test_mbox):
    sender = None
    random_msg = None
    random_from = None
    # Want to make sure we've seen sender before.
    while not sender or sender not in detectors[0].sender_profile:
        i, j = np.random.randint(0, len(test_mbox)), np.random.randint(0, len(test_mbox))
        random_msg = test_mbox[i]
        random_from = test_mbox[j]
        sender = random_from['From']

    if sender == random_msg['From']:
        print ('repeat sender: {}'.format(sender))
    phish = mailbox.mboxMessage()
    phish['From'] = sender
    phish['To'] = random_msg['To']
    phish['Subject'] = random_msg['Subject']
    for key in random_msg.keys():
        phish[key] = random_msg[key]
    phish['From'] = sender
    phish.set_payload("This is the body for a generated phishing email.\n")
    return phish

def generate_data_matrix(phishing_mbox, regular_mbox):
    assert len(regular_mbox) > NUM_PRE_TRAINING, "Not enough data points."
    num_features = len(features)
    data_matrix = np.empty(shape=(NUM_DATA, num_features))

    print("Generating data matrix...")
    row_index = 0
    for i in range(NUM_PRE_TRAINING, len(regular_mbox)):
        for j, detector in enumerate(detectors):
            data_matrix[row_index][j] = float(detector.classify(regular_mbox[i]))
        row_index += 1
    for _ in range(NUM_DATA / 2):
        phish_email = phishing_mbox[i] if phishing_mbox else make_phish(regular_mbox)
        for j, detector in enumerate(detectors):
            data_matrix[row_index][j] = float(detector.classify(phish_email))
        row_index += 1
    return data_matrix

def generate_test_matrix(test_mbox):
    num_features = len(features)
    num_test_points = len(test_mbox)
    test_data_matrix = np.empty(shape=(2 * num_test_points, num_features))

    print("Generating test data matrix...")
    row_index = 0
    for i in range(num_test_points):
        for j, detector in enumerate(detectors):
            test_data_matrix[row_index][j] = float(detector.classify(test_mbox[i]))
        row_index += 1
    for _ in range(num_test_points):
        phish_email = make_phish(test_mbox)
        for j, detector in enumerate(detectors):
            test_data_matrix[row_index][j] = float(detector.classify(phish_email))
        row_index += 1
    return test_data_matrix

def generate_labels(phishing_mbox, regular_mbox):
    assert len(regular_mbox) > NUM_PRE_TRAINING, "Not enough data points."
    label_matrix = np.empty(shape=(NUM_DATA, 1))

    print("Generating label matrix...")
    for i in range(NUM_DATA):
        label_matrix[i][0] = 0 if i < NUM_DATA / 2 else 1
    return label_matrix

def generate_test_labels(test_mbox):
    num_test_points = len(test_mbox)
    test_label_matrix = np.empty(shape=(2 * num_test_points, 1))

    print("Generating test label matrix...")
    for i in range(2 * num_test_points):
        test_label_matrix[i][0] = 0 if i < num_test_points else 1
    return test_label_matrix


######################
# Script Starts Here #
######################

start_time = time.clock()
if os.path.exists(PHISHING_FILENAME):
    phishing_emails = mailbox.mbox(PHISHING_FILENAME)
else:
    print("No phishing emails provided.")
    phishing_emails = None
regular_emails = mailbox.mbox(REGULAR_FILENAME)
# test_emails = mailbox.mbox(TEST_FILENAME)
NUM_PRE_TRAINING = len(regular_emails) - NUM_DATA / 2
detectors = build_detectors(regular_emails)
X = generate_data_matrix(phishing_emails, regular_emails)
Y = generate_labels(phishing_emails, regular_emails)
# test_X = generate_test_matrix(test_emails)
# test_Y = generate_test_labels(test_emails)

file_dict = {}
file_dict['training_data'] = X
file_dict['training_labels'] = Y
# file_dict['test_data'] = test_X
# file_dict['test_labels'] = test_Y
sio.savemat('phishing_data.mat', file_dict)
end_time = time.clock()

print("Data matrix has been generated. There are {} total training points and {} total features.".format(len(X), len(X[0])))
# print("Test matrix has been generated. There are {} total test points and {} total features.".format(len(test_X), len(test_X[0])))
print("The script took {} seconds.".format(end_time - start_time))
