#!/usr/bin/env python

""" 
generate_features.py: Script that reads in spear-phishing and legitimate emails
and converts each training example into a feature vector.

Requirements:
-numpy ('pip install numpy')
-scipy ('pip install scipy')

The output of your file will be a .mat file. The data will be accessible using
the following keys:
    -'training_data'
    -'training_labels'
"""

import mailbox
import numpy as np
import scipy.io as sio

import feature_classes as fc

PHISHING_FILENAME = 'phish.mbox'
# PHISHING_FILENAME = 'matthew_berkeley.mbox'
REGULAR_FILENAME = 'regular.mbox'
# REGULAR_FILENAME = 'Inbox.mbox'
NUM_PRE_TRAINING = 1000

############
# FEATURES #
############
"""
Define your features in feature_classes.py, and add the class name to the
features list below. Feature classes must inherit from the Detector class
defined in detector.py.
"""

features = [
    fc.MessageIdDetectorOne,
    fc.MessageIdDetectorTwo
]

def generate_data_matrix(phishing_mbox, regular_mbox):
    assert len(regular_mbox) > NUM_PRE_TRAINING, "Not enough data points."
    num_data_points = len(phishing_mbox) + len(regular_mbox) - NUM_PRE_TRAINING
    num_features = len(features)
    data_matrix = np.empty(shape=(num_data_points, num_features))
    detectors = [Detector(regular_mbox) for Detector in features]
    print("Building sender profiles for each feature...")
    for detector in detectors:
        detector.create_sender_profile(NUM_PRE_TRAINING)
    print("Generating data matrix...")
    row_index = 0
    for i in range(NUM_PRE_TRAINING, len(regular_mbox)):
        for j, detector in enumerate(detectors):
            data_matrix[row_index][j] = 1 if detector.classify(regular_mbox[i]) else 0
        row_index += 1
    for i in range(len(phishing_mbox)):
        for j, detector in enumerate(detectors):
            data_matrix[row_index][j] = 1 if detector.classify(phishing_mbox[i]) else 0
        row_index += 1
    return data_matrix

def generate_labels(phishing_mbox, regular_mbox):
    assert len(regular_mbox) > NUM_PRE_TRAINING, "Not enough data points."
    num_data_points = len(phishing_mbox) + len(regular_mbox) - NUM_PRE_TRAINING
    label_matrix = np.empty(shape=(num_data_points, 1))
    print("Generating label matrix...")
    for i in range(num_data_points):
        label_matrix[i][0] = 0 if i < len(regular_mbox) - NUM_PRE_TRAINING else 1
    return label_matrix


######################
# Script Starts Here #
######################

phishing_emails = mailbox.mbox(PHISHING_FILENAME)
regular_emails = mailbox.mbox(REGULAR_FILENAME)
X = generate_data_matrix(phishing_emails, regular_emails)
Y = generate_labels(phishing_emails, regular_emails)

file_dict = {}
file_dict['training_data'] = X
file_dict['training_labels'] = Y
sio.savemat('phishing_data.mat', file_dict)

print("Data matrix has been generated. There are {} total training points and {} total features.".format(len(X), len(X[0])))
