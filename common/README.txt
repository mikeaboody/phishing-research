README

The goal of these scripts is to generate a data matrix from a given mbox and
provide a location to perform adhoc testing.

Requirements:
-------------
- Python 2.7
- numpy ('pip install numpy')
- scipy ('pip install scipy')
- editdistance ('pip install editdistance')
- ipwhois ('pip install ipwhois')
- whois ('pip install whois')
- netaddr ('pip install netaddr')

Setup:
------
1) Move a .mbox file containing legitimate emails to this directory and rename it 'regular.mbox'
	- These emails will be used to generate the training data and lables.
2) (optional) Move a .mbox file containing phishy emails to this directory and rename it 'phish.mbox'
	- The script will automatically generate pseudo-phishy emails if you skip this step.
3) Move a .mbox file containing legitimate emails to this directory and rename it 'test.mbox'
	- These emails will be used to generate the test data and labels.

Generating the Data
-------------------
1) Generate the data and test matrices using the following command:
	- python generate_features.py
2) Test that the data matrix was successfully created:
	- python adhoc.py

Adding new detectors:
---------------------
1) New detectors should go in 'feature_classes.py' and should inherit from the Detector class in 'detector.py'.
2) Once you've added your detector class, add it to the 'features' list in 'generate_features.py'.
3) Repeat the steps in 'Generating the Data'.

Performing Analysis
-------------------
See 'adhoc.py' for an example of how to load the generated data and perform some simple analysis.
