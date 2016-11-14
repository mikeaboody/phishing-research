import json
import logging
import os
import shlex
import subprocess
import time

import numpy as np

solvers = ["liblinear", "newton-cg", "lbfgs", "sag"]
tolerances = [1e-4, 0.1]
debug_logger = logging.getLogger('spear_phishing.debug')

def run():
    for solver in solvers:
        for tolerance in tolerances:            
            command = "python debug_training_scripts.py --solver {} --tol {}".format(solver, tolerance)
            args = shlex.split(command)
            process = subprocess.Popen(args)
            start_time = time.time()
            process.poll()
            while process.returncode == None:
                curr_time = time.time()
                if curr_time - start_time > 60 * 10:
                    debug_logger.warn("Terminating process for script: {} after {} seconds".format(command, int(curr_time - start_time)))
                    process.terminate()
                    time.sleep(1) # Sleep for 1 second so return code can be set.
                process.poll()

def check_isnan(input_filename, output_filename):
    training_data = np.load(input_filename)
    train_X = training_data["X"]
    # result will be a tuple of arrays, with the first array being the x-coords, and the 2nd the y-coords
    result = np.where(np.isnan(train_X.astype(np.float)))
    y_indices = result[1]
    counts = {}
    for val in y_indices:
        if val in counts:
            counts[val] += 1
        else:
            counts[val] = 1

    with open(output_filename, 'w') as output:
        json.dump(counts, output)

def check_isinf(input_filename, output_filename):
    training_data = np.load(input_filename)
    train_X = training_data["X"]
    result = np.where(np.isinf(train_X.astype(np.float)))
    y_indices = result[1]
    counts = {}
    for val in y_indices:
        if val in counts:
            counts[val] += 1
        else:
            counts[val] = 1
    with open(output_filename, 'w') as output:
        json.dump(counts, output)

check_isnan("training_data.npz", "../output/nan_indices.txt")
check_isinf("training_data.npz", "../output/inf_indices.txt")

run()
