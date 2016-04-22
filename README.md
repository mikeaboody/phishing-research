### Set Up
1.  Run the following command to clone the repository
    ```{r, engine='bash', count_lines}
    git clone https://github.com/mikeaboody/phishing-research.git
    ```
2.  Make sure you have bro installed and added to your PATH
    * Reference: https://www.digitalocean.com/community/tutorials/how-to-install-bro-ids-2-2-on-ubuntu-12-04
3.  Make sure you have ```pip``` installed
4.  To install all of the necessary Python packages, run the following command from the root directory of the repository
    ```{r, engine='bash', count_lines}
    pip install --user -r requirements.txt
    ```
5. Make sure you have the command-line program ```shuf``` installed.
    * If not, if there’s a way to install GNU coreutils, you can install ```coreutils```, which provides ```gshuf```
    * Then symlink ```shuf``` -> ```gshuf``` somewhere in your PATH.

### Instructions
1.  Gather PCAP files you would like to analyze
    *   Option 1 (recommended): place pcaps in ```broScripts/input/```
    *   Option 2: Edit line 12 in ```broScripts/parse_pcap.py``` so that ```PCAP_DIRECTORY``` is the path to the directory containing the PCAP files
2.  Run the following command from the root directory of the repository you initially cloned
    ```{r, engine='bash', count_lines}
    ./run_all.sh
    ```
3.  There will be a ```common/output``` directory with 3 things, a ```low_volume``` directory, a ```high_volume``` directory, and an ```output.txt``` (you can ignore the ```output.txt```).
The ```low_volume``` directory contains emails from senders who send low volume emails (<1000 emails).  Look at email headers in the JSON file in descending filename order.  Likewise for the high_volume directory.

### How To Run Phish Detector
You should really only have to run
    
    ./run_all.sh
but if the settings seem off or you’d like to run part of the phish detector without doing everything (data, test, model, run), there is an amazing readme written in markdown by the great Jerry Cheng himself in the common folder at “common/phish_detector.md”. In the ideal case, the user shouldn’t have to worry about these settings for an end-to-end test.