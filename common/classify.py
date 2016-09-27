from collections import OrderedDict
import datetime as dt
import json
import logging
import os
import pprint as pp
from subprocess import call
import time

import numpy as np
import scipy.io as sio
from sklearn import linear_model, cross_validation
from sklearn.utils import shuffle
from sklearn.externals import joblib

from memtest import MemTracker

PATH_IND = 0
LEGIT_IND = 1
PROBA_IND = 2
TEST_IND = 3
MESS_ID_IND = 4
TOTAL_SIZE = 5

progress_logger = logging.getLogger('spear_phishing.progress')

class Classify:

    def __init__(self, w, email_path, volume_split, bucket_size, results_dir="output", serial_path="clf.pkl", memlog_freq=-1):
        self.weights = {1.0: w['positive'], 0.0: w['negative']}
        self.clf = linear_model.LogisticRegression(class_weight=self.weights)
        self.email_path = email_path
        self.serial_to_path = serial_path
        self.results_dir = results_dir
        self.bucket_thres = volume_split
        self.bucket_size = bucket_size
        self.feature_names = None
        self.memlog_freq = memlog_freq
        
    def generate_training(self):
        X = None
        Y = None
        found_training_file = False
        logging_interval = 60 # TODO(matthew): Move to config.yaml
        progress_logger.info("Starting to build training matrix.")
        start_time = time.time()
        last_logged_time = start_time
        num_senders_completed = 0
        for root, dirs, files in os.walk(self.email_path):
            curr_time = time.time()
            if (curr_time - last_logged_time) > logging_interval * 60:
                progress_logger.info('Exploring directory #{}'.format(num_senders_completed))
                progress_logger.info('Building training matrix has run for {} minutes'.format(int((curr_time - start_time) / 60)))
                last_logged_time = curr_time
            if 'training.mat' in files:
                found_training_file = True
                path = os.path.join(root, "training.mat")
                data = sio.loadmat(path)
                part_X = data['training_data']
                part_Y = data['training_labels']
                if self.feature_names is None:
                    self.feature_names = data['feature_names']
                if len(part_X) == 0:
                    continue
                if X == None:
                    X = part_X
                    Y = part_Y
                    continue
                X = np.concatenate((X, part_X), axis=0)
                Y = np.concatenate((Y, part_Y), axis=0)
            num_senders_completed += 1
        if not found_training_file:
            raise RuntimeError("Cannot find 'training.mat' files.")
        if X is None:
            raise RuntimeError("Not enough data found in 'training.mat' files. Try running on more pcaps.")

        X, Y = shuffle(X, Y)
        self.X = X
        self.Y = Y
        self.data_size = len(X)
        end_time = time.time()
        min_elapsed, sec_elapsed = int((end_time - start_time) / 60), int((end_time - start_time) % 60)
        progress_logger.info("Finished concatenating training matrix in {} minutes, {} seconds. {} directories seen.".format(min_elapsed, sec_elapsed, num_senders_completed))

    def cross_validate(self):
        progress_logger.info("Starting cross validation.")
        validate_clf = linear_model.LogisticRegression(class_weight=self.weights)
        self.validation_acc = cross_validation.cross_val_score(validate_clf, self.X, self.Y.ravel(), cv=5)
        progress_logger.info("Validation Accuracy: {}".format(self.validation_acc.mean()))

    def train_clf(self):
        progress_logger.info("Starting to train classifier.")
        self.clf.fit(self.X, self.Y.ravel())
        progress_logger.info("Finished training classifier.")
        self.clf_coef = self.clf.coef_[0]

    def serialize_clf(self):
        joblib.dump(self.clf, self.serial_to_path)
        progress_logger.info("Finished serializing.")
        
    def clean_all(self):
        try:
            call(['rm', '-r', self.results_dir])
        except Exception as e:
            pass

    def test_and_report(self):
        """ Assumptions:
         - test.mat exists in directory structure and
           clf is classifier trained on all data matrices.
         - test.mat has data['email_index']
        Results is [path, index, probability]
        """
        self.clean_all() 
        if not os.path.exists(self.results_dir):
            os.makedirs(self.results_dir) 

        logging_interval = 60 # TODO(matthew): Move to config.yaml
        progress_logger.info("Starting to test on data.")
        start_time = time.time()
        last_logged_time = start_time

        results = np.empty(shape=(0, TOTAL_SIZE), dtype='S200')

        end_of_last_memory_track = dt.datetime.now()
        num_senders_completed = 0
        for root, dirs, files in os.walk(self.email_path):
            curr_time = time.time()
            if (curr_time - last_logged_time) > logging_interval * 60:
                progress_logger.info('Exploring directory #{}'.format(num_senders_completed))
                progress_logger.info('Testing has run for {} minutes'.format(int((curr_time - start_time) / 60)))
                last_logged_time = curr_time
            if self.memlog_freq >= 0:
                now = dt.datetime.now()
                time_elapsed = now - end_of_last_memory_track
                minutes_elapsed = time_elapsed.seconds / 60.0
                if minutes_elapsed > self.memlog_freq:
                    MemTracker.logMemory("After completing " + str(num_senders_completed) + " iterations in test_and_report")
                    end_of_last_memory_track = dt.datetime.now()
            if 'test.mat' in files:
                path = os.path.join(root, "test.mat")
                data = sio.loadmat(path)
                test_X = data['test_data']
                sample_size = test_X.shape[0]
                if sample_size == 0:
                    continue
                test_indx = np.arange(sample_size).reshape(sample_size, 1)
                indx = data['email_index'].reshape(sample_size, 1)
                test_mess_id = data['message_id'].reshape(sample_size, 1).astype("S200")
                test_res = self.output_phish_probabilities(test_X, indx, root, test_indx, test_mess_id)
                if test_res is not None:
                    results = np.concatenate((results, test_res), 0)
            num_senders_completed += 1
        
        self.write_as_matfile(results)
        # Deletes message_id column, because no longer needed.
        results = np.delete(results, MESS_ID_IND, 1)
        res_sorted = results[results[:,PROBA_IND].argsort()][::-1]
        self.num_phish, self.test_size = self.calc_phish(res_sorted)
        output = self.filter_output(res_sorted)
        progress_logger.info(pp.pformat(output))
        self.d_name_per_feat = self.parse_feature_names()
        self.pretty_print(output[0], "low_volume")
        self.pretty_print(output[1], "high_volume")
        self.write_summary_output(output)
        end_time = time.time()
        min_elapsed, sec_elapsed = int((end_time - start_time) / 60), int((end_time - start_time) % 60)
        progress_logger.info("Finished testing on data in {} minutes, {} seconds. {} directories tested.".format(min_elapsed, sec_elapsed, num_senders_completed))
    
    def write_as_matfile(self, results):
        # Don't write the test_indx, only [path, indx, phish_prob, message_id]
        results = np.delete(results, TEST_IND, 1)
        output_dict = {}
        output_dict["phish_proba"] = results
        output_dict["column_names"] = ["path_to_email", "index_of_email", "phish_probability", "message_id_of_email"]

        matfile_path = os.path.join(self.results_dir, 'phish_proba.mat')
        sio.savemat(matfile_path, output_dict)

    def calc_phish(self, res_sorted):
        test_size = len(res_sorted)
        num_phish = sum(map(lambda x: 1 if float(x[2]) > 0.5 else 0, res_sorted))
        if test_size == 0:
            return None, "No test matrix."
        return num_phish, test_size

    def pretty_print(self, output, folder_name):
        for i, row in enumerate(output):
            path = row[PATH_IND]
            indx = int(row[LEGIT_IND])
            test_indx = int(row[TEST_IND])
            break_down = self.get_detector_contribution(path, test_indx)
            headers = eval(self.get_email(path, indx))
            headers_dict = self.to_dictionary(headers)
            self.write_file(folder_name, i, headers_dict, row[PROBA_IND], break_down)

    def get_detector_contribution(self, path, test_indx):
        # Removing the ending "legit_emails.log" and adding "test.mat"
        path = path[:-16] + "test.mat"
        data = sio.loadmat(path)
        test_sample = data['test_data'][test_indx]
        product = np.multiply(test_sample, self.clf_coef)
        d_contribution = {}
        curr = None
        for i, d in enumerate(self.d_name_per_feat):
            if curr is None or d != curr:
                curr = d
                d_contribution[curr] = 0
            d_contribution[curr] += product[i]
        return OrderedDict(sorted(d_contribution.items(), key=lambda t: t[1], reverse=True))
        
    def parse_feature_names(self):
        f_names = np.char.strip(self.feature_names, " ")
        # Assumes feature names are formatted as "ExampleDetector-0" meaning the
        # first feature of ExampleDetector. So the next line splits on the "-" and
        # removes the feature number. Feature names are created in
        # generate_features.py
        f_names = np.delete(np.array(list(np.char.rsplit(f_names, "-"))), 1, 1)
        d_names = f_names.flatten()
        return list(d_names)

    def to_dictionary(self, headers):
        d = {}
        for tup in headers:
            d[tup[0]] = tup[1]
        return d

    def write_file(self, folder_name, i, headers_dict, confidence, break_down):
        file_name = str(i) + ".json"
        full_path = os.path.join(self.results_dir, folder_name, file_name)
        directory = os.path.dirname(full_path)
        if not os.path.exists(directory):
            os.makedirs(directory)
        with open(full_path, "w") as output:
            output.write(json.dumps([{"phish_probability": confidence}, break_down, {"headers": headers_dict}], sort_keys=False, indent=4, separators=(",", ": ")))


    def write_summary_output(self, output):
        path = os.path.join(self.results_dir, "summary.txt")
        with open(path, "w+") as out:
            out.write("Data size: {}\n".format(self.data_size))
            out.write("Test size: {}\n".format(self.test_size))
            out.write("# phish detected: {}\n".format(self.num_phish))
            percent = round(self.num_phish / float(self.test_size), 3) if self.num_phish else None
            out.write("% phish detected: {}\n".format(percent))
            out.write("Cross validation acc: {}\n".format(self.validation_acc.mean()))
            out.write("Features coefficients:\n")
            coefs = sorted(zip(map(lambda x: round(x, 4), self.clf_coef), self.feature_names), reverse=True)
            coefs = [x[1] + ": " + str(x[0]) for x in coefs]
            out.write(json.dumps(coefs, indent=2))
            out.write(json.dumps(output, sort_keys=False, indent=4, separators=(",", ": ")))

    def get_email(self, path, indx):
        with open(path) as fp:
            for i, line in enumerate(fp):
                if i == indx:
                    return line
    
    def filter_output(self, lst):
        self.buckets = [0, 0]
        unique_sender = set()
        i = 0
        results = [[], []]
        while sum(self.buckets) < self.bucket_size*2 and i < len(lst):
            path = lst[i][0]
            sender = self.get_sender(path)
            num_emails = sum(1 for line in open(path))
            buckets_full, indx = self.check_buckets(num_emails)
            if sender in unique_sender or buckets_full:
                i += 1
                continue
            unique_sender.add(sender)
            self.buckets[indx] += 1
            results[indx].append(lst[i].tolist())
            i += 1
        return results
            
    def check_buckets(self, num_emails):
        bucket = 0 if num_emails < self.bucket_thres else 1
        return self.buckets[bucket] >= self.bucket_size, bucket
            
    def get_sender(self, path):
        return path.split('/')[-2]
    
    def output_phish_probabilities(self, test_X, indx, path, test_indx, test_mess_id):
        # Outputs matrix with columns:
        # [path, index_in_legit_email, prob_phish, test_indx, message_id]
        # test_indx necessary for relooking up the test_indxth sample of 
        # the test matrix when ranking feature contribution.
        sample_size = test_X.shape[0]
        if sample_size == 0:
            return None
        path_array = np.array([os.path.join(path, "legit_emails.log")])
        path_array = np.repeat(path_array, sample_size, axis=0).reshape(sample_size, 1)
        predictions = self.clf.predict(test_X).reshape(sample_size, 1)
        prob_phish = self.clf.predict_proba(test_X)[:,1].reshape(sample_size, 1)
        prob_phish[prob_phish < float(0.0001)] = 0
        path_id = np.concatenate((path_array, indx), axis=1)
        res = np.empty(shape=(sample_size, 0))
        res = np.concatenate((res, path_id), 1)
        res = np.concatenate((res, prob_phish), 1)
        res = np.concatenate((res, test_indx), 1)
        res = np.concatenate((res, test_mess_id), 1)
        # Assumes prob_phish is 3rd column (index 2) and sorts by that.
        res_sorted = res[res[:,PROBA_IND].argsort()][::-1]
        return res_sorted
