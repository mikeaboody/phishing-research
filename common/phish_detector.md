#Phish Detector Guide
The Phish Detector (```phish_detector.py```) is the user-interface used to generate and serialize the data and test matrices, as well as to train and run the logistic regression model on these matrices. It assumes that a directory structure is set up containing folders with emails in ```.log``` format, organized by sender.

###Configuration File

The Phish Detector expects to find a YAML configuration file named ```config.yaml``` in the same directory that this python script is in. A sample configuration of ```config.yaml``` is:

```
#Configuration file for PhishDetector

#Data and Test Matrix Configurations
root_dir:                       ../broScripts/output
sender_profile_percentage:      0.1
data_matrix_percentage:         0.2
test_matrix_percentage:         0.7

#Model Training and Classification Settings
weights:
    positive:                   0.5
    negative:                   1.0
model_path_out:                 .
result_path_out:                .
results_size:                   10
emails_threshold:               1000
detectors:
    DateTimezoneDetector:     1
    MessageIdDetectorOne:     1
    messageIDDomain_Detector: 1
    ContentTypeDetector:      1
    OrderOfHeaderDetector:    1
    XMailerDetector:          1
    ReceivedHeadersDetector:  1
    DateFormatDetector:       1

#Do not modify unless you are certain what you are doing
regular_filename:               legit_emails.log
phish_filename:                 phish_emails.log
```

The config file is a series of key-value pairs. The fields work as follows:

- ```root_dir```: The root directory of the log files. The script will recursively search through folders inside this root\_dir to find files names ```regular_filename``` and ```phish_filename```.
- ```sender_profile_percentage```: The percentage of emails used to create the sender profile.
- ```data_matrix_percentage```: The percentage of emails used to create the data matrix.
- ```test_matrix_percentage```: The percentage of emails used to create the test matrix.
- ```weights```: Logistic Regression settings for weighting positive (phishing) and negative (authentic) emails during training.
- ```model_path_out```: The path to serialize the logistic regression model to.
- ```result_path_out```: The path to save output results to.
- ```results_size```: The number of results to store for each low and high frequency senders. The top ```results_size``` positive classifications for each will be saved.
- ```emails_threshold```: Senders who send more than ```emails_threshold``` emails will be classified as a high frequency sender, while senders lower than ```emails_threshold``` are classified as a low frequency sender.
- ```detectors```: A list of detectors that can be used to generate features. A value of 1 corresponds to on, and a value of 0 corresponds to off.
- ```regular_filename```: Filename corresponding to normal emails.
- ```phish_filename```: Filename corresponding to generated phishing emails.

###How to Run Phish Detector

The Phish Detector takes in flags to specify what to run. To find out what each flag does, run:

```python phish_detector.py --help```

You must run ```phish_detector.py``` with at least one flag, or it will complain. The help command summarizes how to run in the following manner:

```
usage: phish_detector.py [-h] [--all] [--gen_all] [--gen_data] [--gen_test]
                         [--gen_model] [--classify] [--no_parallel]

Mange spear fishing detector.

optional arguments:
  -h, --help     show this help message and exit
  --all          Generate and serialize data matrix, test matrix, and ML
                 model, then run ML model on test matrix
  --gen_all      Generate and serialize data matrix, test matrix, and ML model
  --gen_data     Generate and serialize data matrix
  --gen_test     Generate and serialize test matrix
  --gen_model    Generate and serialize ML model
  --classify     Run ML model on test matrix
  --no_parallel  Generate features for matrices serially.
```