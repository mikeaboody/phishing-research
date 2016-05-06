import numpy as np
import scipy.io as sio
from sklearn import linear_model, cross_validation
from sklearn.utils import shuffle
import pprint as pp
from sklearn.externals import joblib
import os
import json

class Classify:
    
    def __init__(self, w, path, volume_split, bucket_size, results_path="output.txt", serial_path="clf.pkl"):
        self.weights = {1.0: w['positive'], 0.0: w['negative']}
        self.clf = linear_model.LogisticRegression(class_weight=self.weights)
        self.path = path
        self.serial_to_path = serial_path
        self.results_path = results_path
        self.bucket_thres = volume_split
        self.bucket_size = bucket_size 
        
    def generate_training(self):
        X = None
        Y = None
        found_training_file = False
        for root, dirs, files in os.walk(self.path): 
            if 'training.mat' in files:
                found_training_file = True
                path = os.path.join(root, "training.mat")
                data = sio.loadmat(path)
                part_X = data['training_data']
                part_Y = data['training_labels']
                self.names = data['feature_names']
                if len(part_X) == 0:
                    continue
                if X == None:
                    X = part_X
                    Y = part_Y
                    continue
                X = np.concatenate((X, part_X), axis=0)
                Y = np.concatenate((Y, part_Y), axis=0)
        if not found_training_file:
            raise RuntimeError("Cannot find 'training.mat' files.")
        if X == None:
            raise RuntimeError("Not enough data found in 'training.mat' files. Try running on more pcaps.")

        X, Y = shuffle(X, Y)
        self.X = X
        self.Y = Y
        self.data_size = len(X)
        print("Finished concatenating training matrix.")

    def cross_validate(self):
        validate_clf = linear_model.LogisticRegression(class_weight=self.weights)
        self.validation_acc = cross_validation.cross_val_score(validate_clf, self.X, self.Y.ravel(), cv=5)
        print("Validation Accuracy: {}".format(self.validation_acc.mean()))

    def train_clf(self):
        self.clf.fit(self.X, self.Y.ravel())
        print("Finished training classifier.")

    def serialize_clf(self):
        joblib.dump(self.clf, self.serial_to_path)
        print("Finished serializing.")
        
    def test_and_report(self):
        """ Assumptions:
         - test.mat exists in directory structure and
           clf is classifier trained on all data matrices.
         - test.mat has data['email_index']
        Results is [path, index, probability]
        """
        results = np.empty(shape=(0, 3), dtype='S200')
        
        for root, dirs, files in os.walk(self.path):
            if 'test.mat' in files:
                path = os.path.join(root, "test.mat")
                data = sio.loadmat(path)
                test_X = data['test_data']
                sample_size = test_X.shape[0]
                indx = data['email_index'].reshape(sample_size, 1)
                test_res = self.output_phish_probabilities(test_X, indx, root)
                if test_res != None:
                    results = np.concatenate((results, test_res), 0)
        
        res_sorted = results[results[:,2].argsort()][::-1]
        self.num_phish, self.test_size = self.calc_phish(res_sorted)
        output = self.filter_output(res_sorted)
        pp.pprint(output)
        self.pretty_print(output[0], "low_volume")
        self.pretty_print(output[1], "high_volume")
        self.write_txt(output)

    def calc_phish(self, res_sorted):
        test_size = len(res_sorted)
        num_phish = sum(map(lambda x: 1 if float(x[2]) > 0.5 else 0, res_sorted))
        if test_size == 0:
            return None, "No test matrix."
        return num_phish, test_size

    def pretty_print(self, output, folder_name):
        for i, row in enumerate(output):
            path = row[0]
            indx = int(row[1])
            headers = eval(self.get_email(path, indx))
            headers_dict = self.to_dictionary(headers)
            self.write_file(folder_name, i, headers_dict, row[2])

    def to_dictionary(self, headers):
        d = {}
        for tup in headers:
            d[tup[0]] = tup[1]
        return d

    def write_file(self, folder_name, i, headers_dict, confidence):
        file_name = str(i) + ".json"
        full_path = os.path.join(self.results_path, folder_name, file_name)
        directory = os.path.dirname(full_path)
        if not os.path.exists(directory):
            os.makedirs(directory)
        with open(full_path, "w") as output:
            output.write(json.dumps([{"phish_probability": confidence}, {"headers": headers_dict}], sort_keys=False, indent=4, separators=(",", ": ")))

    def write_txt(self, output):
        path = os.path.join(self.results_path, "output.txt")
        with open(path, "w+") as out:
            out.write("Data size: {}\n".format(self.data_size))
            out.write("Test size: {}\n".format(self.test_size))
            out.write("# phish detected: {}\n".format(self.num_phish))
            percent = round(self.num_phish / float(self.test_size), 3) if self.num_phish else None
            out.write("% phish detected: {}\n".format(percent))
            out.write("Cross validation acc: {}\n".format(self.validation_acc.mean()))
            out.write("Features coefficients:\n")
            coefs = sorted(zip(map(lambda x: round(x, 4), self.clf.coef_[0]), 
                self.names), reverse=True)
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
            
    def check_buckets(self, num_emails):
        bucket = 0 if num_emails < self.bucket_thres else 1
        return self.buckets[bucket] >= self.bucket_size, bucket
            
    def get_sender(self, path):
        return path.split('/')[-2]
    
    def output_phish_probabilities(self, test_X, indx, path):
        # [PATH, INDEX, prob_phish]
        sample_size = test_X.shape[0]
        if sample_size == 0:
            return None
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
    
