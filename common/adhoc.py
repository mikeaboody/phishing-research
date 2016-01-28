import matplotlib.pyplot as pyplot
import numpy as np
import scipy.io as sio
from sklearn import ensemble, linear_model, neighbors, neural_network, svm
from sklearn.utils import shuffle

DATA_PATH = 'phishing_data.mat'
VALIDATION_PERCENT = 0.1

data = sio.loadmat(DATA_PATH)
X = data['training_data']
Y = data['training_labels']
X, Y = shuffle(X, Y)
N, d = len(X), len(X[0])
validation_index = int((1 - VALIDATION_PERCENT) * N)
# test_X = data['test_data']
# test_Y = data['test_labels']

test_methods = {
    'linear svm': svm.LinearSVC(),
    'logistic regression': linear_model.LogisticRegression(),
    'nearest centroid': neighbors.KNeighborsClassifier(n_neighbors=5),
    'random forest': ensemble.RandomForestClassifier(n_estimators=10)
    # 'neural network': neural_network.MLPClassifier()
}

def test():
    for key, value in test_methods.items():
        train_X, train_Y = X[:validation_index], Y[:validation_index]
        val_X, val_Y = X[validation_index:], Y[validation_index:]
        clf = value
        clf.fit(train_X, train_Y.ravel())

        score = clf.score(val_X, val_Y)
        print("Using {} training examples and {}, score is {}.".format(
            validation_index, key, score))

def sample_data():
    for i in range(100):
        print X[i], Y[i]

def validate_data():
    total_phish = 0
    total_legit = 0
    detection_fail = np.zeros(d)
    false_classify = np.zeros(d)
    for i in range(N):
        if Y[i][0] == 0:
            total_legit += 1
            for j in range(d):
                if X[i][j] != Y[i][0]:
                    false_classify[j] += 1
        elif Y[i][0] == 1:
            total_phish += 1
            # print X[j]
            for j in range(d):
                if X[i][j] != Y[i][0]:
                    detection_fail[j] += 1
    print("Total number of phishing emails: {}. Failed detection rates: {}".format(total_phish, np.divide(detection_fail, total_phish)))
    print("Total number of legit emails: {}. False classify rates: {}".format(total_legit, np.divide(false_classify, total_legit)))
    """
    Total number of phishing emails: 2500. Failed detection rates: [ 0.808   0.808   0.9936  0.9988  0.9996]
    Total number of legit emails: 2500. False classify rates: [ 0.1984  0.1984  0.0288  0.008   0.004 ]
    Out of 2500 phish, 1013 new.
    """

# test()
# sample_data()
validate_data()