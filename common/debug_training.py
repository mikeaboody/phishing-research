import logging
import os
import shlex
import subprocess
import time

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

run()
