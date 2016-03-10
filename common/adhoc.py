import matplotlib.pyplot as pyplot
import numpy as np
import scipy.io as sio
from sklearn import ensemble, linear_model, neighbors, neural_network, svm
from sklearn.utils import shuffle
import pprint as pp

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
names = data['feature_names']

weights = {
    1.0: .5,
    0.0: 1
}

test_methods = {
    'linear svm': svm.LinearSVC(dual=False, class_weight=weights),
    'logistic regression': linear_model.LogisticRegression(class_weight=weights),
    # 'nearest centroid': neighbors.KNeighborsClassifier(n_neighbors=5, class_weight=weights),
    'random forest': ensemble.RandomForestClassifier(n_estimators=10, class_weight=weights)
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
        detect_rate, false_classify_rate = score2(clf, val_X, val_Y.ravel())
        print("Using {} training examples and {}, detection rate is {} and false classification rate is {}.\n".format(
            validation_index, key, detect_rate, false_classify_rate))

def test2():
    for key, value in test_methods.items():
        clf = value
        clf.fit(X, Y.ravel())
        if key == "random forest":
            #print("Features sorted by their mean decrease impurity score:")
            #pp.pprint(sorted(zip(map(lambda x: round(x, 4), clf.feature_importances_), names), reverse=True))
            rf = ensemble.RandomForestClassifier(n_estimators=10, class_weight=weights)
            from sklearn.cross_validation import ShuffleSplit
            from sklearn.metrics import accuracy_score
            from collections import defaultdict
            scores = defaultdict(list)
            Yn = Y.ravel()
            #crossvalidate the scores on a number of different random splits of the data
            for train_idx, test_idx in ShuffleSplit(len(X), 100, .3):
                X_train, X_test = X[train_idx], X[test_idx]
                Y_train, Y_test = Yn[train_idx], Yn[test_idx]
                r = rf.fit(X_train, Y_train)
                acc = accuracy_score(Y_test, rf.predict(X_test))
                for i in range(X.shape[1]):
                    X_t = X_test.copy()
                    np.random.shuffle(X_t[:, i])
                    shuff_acc = accuracy_score(Y_test, rf.predict(X_t))
                    scores[names[i]].append((acc-shuff_acc)/acc)
            print("Features sorted by their score:")
            pp.pprint(sorted([(round(np.mean(score), 4), feat) for
              feat, score in scores.items()], reverse=True))

        elif key == 'logistic regression':
            print("Feature coefficients:")
            pp.pprint(sorted(zip(map(lambda x: round(x, 4), clf.coef_[0]), names), reverse=True))

        detect_rate, false_classify_rate = score2(clf, test_X, test_Y.ravel())
        print("Using {} training examples and {}, detection rate is {} and false classification rate is {}.\n".format(
            N, key, detect_rate, false_classify_rate))

def score2(classifier, val_X, val_Y):
    """Returns detection rate and false_classification rate."""
    predictions = classifier.predict(val_X)
    tp = np.count_nonzero(np.logical_and(predictions == 1, val_Y == 1))
    fp = np.count_nonzero(np.logical_and(predictions == 1, val_Y == 0))
    tn = np.count_nonzero(np.logical_and(predictions == 0, val_Y == 0))
    fn = np.count_nonzero(np.logical_and(predictions == 0, val_Y == 1))
    dr = float(tp) / (tp + fn)
    fcr = float(fp) / (fp + tn)
    print(("True positives: {}\n"
           "False positives: {}\n"
           "True negatives: {}\n"
           "False negatives: {}\n"
           "Detection rate: {}\n"
           "False classification rate: {}\n"
           .format(tp, fp, tn, fn, dr, fcr)))

    return dr, fcr

def sample_data():
    for i in range(100):
        print (X[i], Y[i])

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
            for j in range(d):
                if X[i][j] != Y[i][0]:
                    detection_fail[j] += 1
    print("Total number of phishing emails: {}. Detection rates: {}".format(total_phish, 1 - np.divide(detection_fail, total_phish)))
    print("Total number of legit emails: {}. False classify rates: {}".format(total_legit, np.divide(false_classify, total_legit)))
    """
    Total number of phishing emails: 2500. Failed detection rates: [ 0.808   0.808   0.9936  0.9988  0.9996]
    Total number of legit emails: 2500. False classify rates: [ 0.1984  0.1984  0.0288  0.008   0.004 ]
    Out of 2500 phish, 1013 new.
    """

test2()
