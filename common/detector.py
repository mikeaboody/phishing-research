import abc
from random import randint
import mailbox
import re

class Detector(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, regular_mbox):
        self.inbox = regular_mbox

    @abc.abstractmethod
    def create_sender_profile(self, num_samples):
        """Creates sender to profile map.

        Keyword arguments:
        num_samples -- number of samples to train sender profile on.

        Sets self.sender_profile to a dictionary mapping senders to profiles.

        Returns self.sender_profile.
        """
        return

    @abc.abstractmethod
    def classify(self, phish):
        """Determine if phish is detected as a phishing email by checking if
           it is in the sender's profile.

        Keyword arguments:
        phish -- an instance of mailbox.Message representing the message to
        classify.

        Returns True if the detector classifies phish as a phishy email, False
        otherwise.
        """
        return

    @abc.abstractmethod
    def modify_phish(self, phish, msg):
        """Adds the desired email header field(s) from msg to phish.

        Keyword arguments:
        msg -- an instance of mailbox.Message representing the original email.
        phish -- an instance of mailbox.Message representing the generated
        phishy email.

        Note: Once you set an email header field in a mailbox.Message instance,
        that key, value pair becomes immutable.

        Returns phish.
        """
        return
                          
    def extract_from(self, msg):
        """Extracts the sender from an email.

        Keyword arguments:
        msg -- an instance of mailbox.Message

        Returns the sender stored in msg's From header.
        """
        return msg["From"]

    def make_phish(self):
        """Generates a phishy email."""
        has_sender = None
        random_msg = None
        random_from = None
        while not has_sender:
            random_msg = self.inbox[randint(0, len(self.inbox)-1)]
            random_from = self.inbox[randint(0, len(self.inbox)-1)]
            has_sender = self.extract_from(random_from)
            
        phish = mailbox.mboxMessage()
        phish['From'] = random_from['From']
        phish['To'] = random_msg['To']
        phish['Subject'] = random_msg['Subject'] 
        phish = self.modify_phish(phish, random_msg)
        phish.set_payload("This is the body for a generated phishing email.\n")
        return phish
    
    def run_trials(self, num_trials=1000):
        """Determines the classification rate of this detector.

        Keyword arguments:
        num_trials -- number of trials to test on.

        Returns the proportion of phishy emails that this detector successfully
        detected.
        """
        self.detected = 0
        for i in range(num_trials):
            phish = self.make_phish()
            if self.classify(phish):
                self.detected += 1
        return float(self.detected) / num_trials * 100
