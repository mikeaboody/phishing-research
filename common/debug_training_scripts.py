import argparse
import sys
import time

import numpy as np
from sklearn import linear_model

fp = open('../output/debug.log', 'a')

parser = argparse.ArgumentParser(description='Debug the training step of the classifier.')
parser.add_argument('--solver', dest="solver", type=str, default="liblinear")
parser.add_argument('--tol', dest="tol", type=float, default=1e-4)

args = parser.parse_args()

training_data = np.load("training_data.npz")
# train_X = training_data["X"][1:,:] # We don't need feature names
train_X = training_data["X"]
train_Y = training_data["Y"]

class_weights = {1.0: 0.5, 0.0: 1.0}

start_time = time.time()
clf = linear_model.LogisticRegression(class_weight=class_weights,
                                      solver=args.solver,
                                      tol=args.tol,
                                      verbose=1)
clf.fit(train_X, train_Y.ravel())
end_time = time.time()
msg = "Using solver: {} and tolerance: {}, the test took {} seconds.".format(args.solver, args.tol, int(end_time - start_time))
fp.write(msg + "\n")
print(msg)
fp.close()
