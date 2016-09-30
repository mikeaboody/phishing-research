### Set Up
1.  Run the following command to clone the repository

    	git clone https://github.com/mikeaboody/phishing-research.git
2.  Make sure you have bro installed and added to your PATH
    * Reference: https://www.digitalocean.com/community/tutorials/how-to-install-bro-ids-2-2-on-ubuntu-12-04
3.  Make sure you have ```pip``` installed
4.  To install all of the necessary Python packages, run the following command from the root directory of the repository

    	pip install --user -r requirements.txt
    	
    If you run into issues installing scipy and scikit-learn, try the following commands on FreeBSD:
    
        cd /usr/ports/science/py-scipy && make install clean
    
    or
    
        cd /usr/ports/science/py-scikit-learn && make install clean

5. Make sure you have the command-line program ```shuf``` installed.
    * If not, if there’s a way to install GNU coreutils, you can install ```coreutils```, which provides ```gshuf```
    * Then symlink ```shuf``` -> ```gshuf``` somewhere in your PATH.

### Instructions
1.  Gather PCAP files you would like to analyze
    *   Option 1 (recommended): place your pcaps in ```broScripts/input/``` (and delete the ```input000.pcap``` and ```input001.pcap``` that were already there)
    *   Option 2: Edit line 12 in ```broScripts/parse_pcap.py``` so that ```PCAP_DIRECTORY``` is the path to the directory containing the PCAP files
2.  Delete any existing logs (in the root directory of the repository you cloned) that may be left over from prior runs:
    	rm output/*.log
3.  Run the following command from the root directory of the repository you initially cloned

    	python spear_phishing_detector.py --all
4.  There will be a ```common/output``` directory with 3 things, a ```low_volume``` directory, a ```high_volume``` directory, and an ```output.txt``` (you can ignore the ```output.txt```).
The ```low_volume``` directory contains emails from senders who send low volume emails (<1000 emails).  Look at email headers in the JSON file in descending filename order.  Likewise for the high_volume directory.

5. There will also be an ```output``` directory with 4 different files:  ```current.log```, ```debug.log```, ```memory.log```, and ```progress.log```. ```current.log``` has all logs, ```debug.log``` has error logs, ```memory.log``` has logs on memory profiling, and ```progress.log``` contains logs keeping track of the progress of the detector. ```current.log``` and ```debug.log``` contain sensitive information.  ```progress.log``` and ```memory.log``` have been sanitized and shouldn't contain any sensitive/confidential information.

### How To Run Phish Detector
You should really only have to run
    
    python spear_phishing_detector.py --all
but if the settings seem off or you’d like to run part of the phish detector without doing everything (data, test, model, run), there is an amazing readme written in markdown by the great Jerry Cheng himself in the common folder at “common/phish_detector.md”. To use these other settings, you will have to use the run_all script until the functionality is integrated with spear_phishing_detector.py. In the ideal case, the user shouldn’t have to worry about these settings for an end-to-end test.
