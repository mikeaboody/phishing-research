import matplotlib.pyplot as pyplot
import numpy as numpy
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
test_X = data['test_data']
test_Y = data['test_labels']

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
    for i in range(10):
        print X[i], Y[i]

test()
# sample_data()