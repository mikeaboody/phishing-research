import abc
from random import randint
import inbox
import parse_sender
import numpy as np

class Detector(object):
    __metaclass__ = abc.ABCMeta
    """Length of list returned by classify()."""
    NUM_HEURISTICS = 1
    USE_NAME = False

    def __init__(self, regular_mbox):
        self.inbox = regular_mbox
        self._already_created = False

    @abc.abstractmethod
    def update_sender_profile(self, email):
        """Updates sender to profile map with a single email.

        Keyword arguments:
        email -- the email message to add to the sender profile
        """
        return

    def create_sender_profile(self, num_samples):
        """Creates sender to profile map.

        Keyword arguments:
        num_samples -- number of samples to train sender profile on.

        Sets self.sender_profile to a dictionary mapping senders to profiles.
        """
        if self._already_created:
            raise RuntimeError("Tried to call create_sender_profile() twice on same detector")
        for i in range(num_samples):
            email = self.inbox[i]
            self.update_sender_profile(email)
        self._already_created = True

    @abc.abstractmethod
    def classify(self, phish):
        """Determine if phish is detected as a phishing email by checking if
           it is in the sender's profile.

        Keyword arguments:
        phish -- an instance of mailbox.Message representing the message to
        classify.

        Returns a Python list of floats representing scores from various
        heuristics.

        (Soon to be deprecated)
        For backwards compatibility, also supports returning a single boolean if
        there is only 1 heuristic. This support will be removed in future
        versions.
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
        from_header = msg["From"]
        if Detector.USE_NAME:
            return parse_sender.extract_name(from_header)
        else:
            return parse_sender.extract_full_from(from_header)

    def make_phish(self):
        """Generates a phishy email."""
        has_sender = None
        random_msg = None
        random_from = None
        while not has_sender:
            random_msg = self.inbox[randint(0, len(self.inbox)-1)]
            random_from = self.inbox[randint(0, len(self.inbox)-1)]
            has_sender = self.extract_from(random_from)
            
        phish = inbox.Inbox()
        phish['From'] = random_from['From']
        phish['To'] = random_msg['To']
        phish['Subject'] = random_msg['Subject'] 
        phish = self.modify_phish(phish, random_msg)
        return phish

    def log_transform(self, x):
        return np.log(x + 1)
