from collections import OrderedDict
import datetime as dt
import json
import logging
import os
import pprint as pp
from subprocess import call
import sys
import time

import numpy as np
import scipy.io as sio
from sklearn import linear_model, model_selection
from sklearn.utils import shuffle
from sklearn.externals import joblib

from memtest import MemTracker
from priorityQueue import PriorityQueue

PATH_IND = 0
LEGIT_IND = 1
PROBA_IND = 2
TEST_IND = 3
MESS_ID_IND = 4
TOTAL_SIZE = 5

progress_logger = logging.getLogger('spear_phishing.progress')
debug_logger = logging.getLogger("spear_phishing.debug")

class Classify:

    def __init__(self, w, email_path, volume_split, bucket_size, results_dir="output", serial_path="clf.pkl", memlog_freq=-1, debug_training=False):
        self.weights = {1.0: w['positive'], 0.0: w['negative']}
        self.clf = linear_model.LogisticRegression(class_weight=self.weights)
        self.email_path = email_path
        self.serial_to_path = serial_path
        self.results_dir = results_dir
        self.bucket_thres = volume_split
        self.bucket_size = bucket_size
        self.feature_names = None

        self.memlog_freq = memlog_freq
        self.debug_training = debug_training

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
        # Save training data matrix and training labels to training_data.npz.
        # np.savez("training_data", X=np.vstack([self.feature_names, self.X]), Y=self.Y)
        np.savez("training_data", X=self.X, Y=self.Y)
        self.data_size = len(X)
        end_time = time.time()
        min_elapsed, sec_elapsed = int((end_time - start_time) / 60), int((end_time - start_time) % 60)
        progress_logger.info("Finished concatenating training matrix in {} minutes, {} seconds. {} directories seen.".format(min_elapsed, sec_elapsed, num_senders_completed))

    def cross_validate(self):
        progress_logger.info("Starting cross validation.")
        validate_clf = linear_model.LogisticRegression(class_weight=self.weights)
        predictions = model_selection.cross_val_predict(validate_clf, self.X, self.Y.ravel(), cv=5)
        fp_count = 0.0
        tp_count = 0.0
        fn_count = 0.0
        tn_count = 0.0
        miscount = 0.0
        for i in range(len(predictions)):
            prediction = predictions[i]
            expected = self.Y[i][0]
            if prediction == 1 and expected == 1:
                tp_count += 1
            elif prediction == 1 and expected == 0:
                fp_count += 1
            elif prediction == 0 and expected == 1:
                fn_count += 1
            elif prediction == 0 and expected == 0:
                tn_count += 1
            else:
                miscount += 1
        if miscount > 0:
            debug_logger.warn("During cross validation, found {} miscounts.".format(miscount))
        total_count = fp_count + tp_count + fn_count + tn_count
        self.validation_accuracy = (tp_count + tn_count) / total_count if total_count != 0 else 0.0
        fp_rate = fp_count / (fp_count + tn_count) if fp_count + tn_count != 0 else 0.0
        fn_rate = fn_count / (fn_count + tp_count) if fn_count + tp_count != 0 else 0.0
        progress_logger.info("Confusion matrix - True positives: {}, False positives: {}, False negatives: {}, True negatives: {}".format(
            tp_count, fp_count, fn_count, tn_count))
        progress_logger.info("Validation Accuracy: {}".format(self.validation_accuracy))
        progress_logger.info("False positive rate: {}".format(fp_rate))
        progress_logger.info("False negative rate: {}".format(fn_rate))

    def train_clf(self):
        progress_logger.info("Starting to train classifier. Training on {} data points and {} features.".format(self.X.shape[0], self.X.shape[1]))
        # If debug mode, run debug script and then exit without executing the rest of the pipeline.
        if self.debug_training:
            import debug_training
            sys.exit(0)
        else:
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

        # creates this file in common/output
        email_probabilities = open(os.path.join("output", "email_probabilities.txt"), "w")

        low_volume_top_10 = PriorityQueue()
        high_volume_top_10 = PriorityQueue()

        numPhish, testSize = 0, 0
        numEmails4Sender = {}

        logging_interval = 60 # TODO(matthew): Move to config.yaml
        progress_logger.info("Starting to test on data.")
        start_time = time.time()
        last_logged_time = start_time

        results = np.zeros(shape=(0, TOTAL_SIZE), dtype='S200')

        end_of_last_memory_track = dt.datetime.now()
        num_senders_completed = 0

        num_message_id_failed = 0
        total_completed = 0

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
                try:
                    test_mess_id = data['message_id'].reshape(sample_size, 1).astype("S200")
                except ValueError as e:
                    debug_logger.info("data['message_id']: " + str(data['message_id']))
                    progress_logger.info("Size of data['message_id']: " + str(data['message_id'].shape))
                    progress_logger.info("Size of data['test_data']: " + str(data['test_data'].shape))
                    progress_logger.info("sample_size: " + str(sample_size))
                    progress_logger.exception(e)
                    num_message_id_failed += 1
                    continue
                test_res = self.output_phish_probabilities(test_X, indx, root, test_indx, test_mess_id)
                if test_res is not None:
                    for email in test_res:
                        testSize += 1
                        sender = self.get_sender(email[0])
                        emailPath = email[0]
                        probability = float(email[2])
                        message_ID = email[4].strip(" ")
                        if probability > 0.5:
                            numPhish += 1

                        # caches the num_emails value for each sender
                        if sender not in numEmails4Sender:
                            num_emails = sum(1 for line in open(emailPath))
                            numEmails4Sender[sender] = num_emails
                        else:
                            num_emails = numEmails4Sender[sender]

                        # checks which priority queue to add item to
                        if num_emails < self.bucket_thres:
                            low_volume_top_10.push(email, probability)
                        else:
                            high_volume_top_10.push(email, probability)

                        # writes an email's message ID and phish probability to a file
                        email_probabilities.write(message_ID + "," + str(probability) + "\n")
                    total_completed += 1
        progress_logger.info("total # of times size of data['message_id'] != sample_size: " + str(num_message_id_failed))
        progress_logger.info("total # of successes: " + str(total_completed))

        email_probabilities.close()
        self.num_phish, self.test_size = numPhish, testSize
        low_volume_output = low_volume_top_10.createOutput()
        high_volume_output = high_volume_top_10.createOutput()
        output = [low_volume_output, high_volume_output]

        # DEBUG information - don't print to main log
        # debug_logger.info(pp.pformat(output))

        self.d_name_per_feat = self.parse_feature_names()
        self.pretty_print(low_volume_output, "low_volume")
        self.pretty_print(high_volume_output, "high_volume")
        self.write_summary_output(output)

        end_time = time.time()
        min_elapsed, sec_elapsed = int((end_time - start_time) / 60), int((end_time - start_time) % 60)
        progress_logger.info("Finished testing on data in {} minutes, {} seconds. {} directories tested.".format(min_elapsed, sec_elapsed, num_senders_completed))

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
            out.write("Cross validation acc: {}\n".format(self.validation_accuracy))
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
