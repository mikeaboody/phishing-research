import matplotlib.pyplot as pyplot
import numpy as np
import scipy.io as sio
from sklearn import ensemble, linear_model, neighbors, neural_network, svm
from sklearn.utils import shuffle
import pprint as pp
from sklearn.externals import joblib
import os

class Classify:
    
    def __init__(w, path, volume_split, bucket_size, serial_path="clf.pkl"):
        weights = {1.0: w[0], 0.0: w[1]}
        self.clf = linear_model.LogisticRegression(class_weight=weights)
        self.path = path
        self.serial_to_path = serial_path
        self.bucket_thres = volume_split
        self.bucket_size = bucket_size 
        
    def generate_training():
        X = None
        Y = None
        for root, dirs, files in os.walk(self.path): 
            if 'training.mat' in files:
                data = sio.loadmat(root + '/training.mat')
                part_X = data['training_data']
                part_Y = data['training_labels']
                if X == None:
                    X = part_X
                    Y = part_Y
                    continue
                X = np.concatenate((X, part_X), axis=0)
                Y = np.concatenate((Y, part_Y), axis=0)
        X, Y = shuffle(X, Y)
        self.X = X
        self.Y = Y
        print("Finished concatenating training matrix")


    def train_clf():
        self.clf.fit(self.X, self.Y.ravel())
        print("Finished training classifer")

    def serialize_clf():
        joblib.dump(self.clf, self.serial_to_path)
        print("Finished serializing")
        
    def test_and_report():
        """ Assumptions:
         - test.mat exists in directory structure and
           clf is classifier trained on all data matrices.
         - test.mat has data['email_index']
        Results is [path, index, probability]
        """
        results = np.empty(shape=(0, 3))
        
        for root, dirs, files in os.walk(self.path):
            if 'test.mat' in files:
                data = sio.loadmat(root + '/test.mat')
                test_X = data['test_data']
                sample_size = test_X.shape[0]
                indx = data['email_index'].reshape(sample_size, 1)
                test_res = self.output_phish_probabilities(test_X, indx, root)
                results = np.concatenate((results, test_res), 0)
        
        res_sorted = results[results[:,2].argsort()][::-1]
        output = self.filter_output(res_sorted)
        pp.pprint(output)
    
    def filter_output(lst):
        self.buckets = [0, 0]
        unique_sender = set()
        i = 0
        results = [[], []]
        while sum(self.buckets) < self.bucket_size*2 and i < len(lst):
            path = lst[i][0]
            sender = self.get_sender(path)
            num_emails = sum(1 for line in open(path + "/legit_emails.log"))
            buckets_full, indx = self.check_buckets(num_emails)
            if sender in unique_sender or buckets_full:
                i += 1
                continue
            unique_sender.add(sender)
            self.buckets[indx] += 1
            lst[i][0] += "/legit_emails.log"
            results[indx].append(lst[i].tolist())
            i += 1
        return results
            
    def check_buckets(num_emails):
        bucket = 0 if num_emails < self.bucket_thres else 1
        return self.buckets[bucket] >= self.bucket_size, bucket
            
    def get_sender(path):
        # Assumes SENDER is third to last.
        return path.split('/')[-3]
    
    def output_phish_probabilities(test_X, indx, path):
        # [PATH, INDEX, prob_phish]
        sample_size = test_X.shape[0]
        path_array = np.array([path])
        path_array = np.repeat(path_array, sample_size, axis=0).reshape(sample_size, 1)
        predictions = self.clf.predict(test_X).reshape(sample_size, 1)
        prob_phish = self.clf.predict_proba(test_X)[:,1].reshape(sample_size, 1)
        path_id = np.concatenate((path_array, indx), axis=1)
        res = np.empty(shape=(sample_size, 0))
        res = np.concatenate((res, path_id), 1)
        res = np.concatenate((res, prob_phish), 1)
        # Assumes prob_phish is 3rd column and sorts by that.
        res_sorted = res[res[:,2].argsort()][::-1]
        return res_sorted
    
