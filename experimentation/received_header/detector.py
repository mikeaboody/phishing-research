import abc
from random import randint
import mailbox
import re


class Detector(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def create_sender_profile(self):
        """Creates sender to profile map.
           Ex: sender_profile = {}
               sender_profile["jenna"] = set(["text/plain", "multipart/mixed"])
           return: sender_profile.
        """
        return

    @abc.abstractmethod
    def classify(self, phish):
        """Determine if phish is detected as a phishing email by checking if
           it is in the sender's profile.
           input: type(phish) = mailbox.Message
           return: boolean value. """
        return

    @abc.abstractmethod
    def modify_phish(self, phish, msg):
        """Adds the desired email header field from msg to phish.
           input: type(msg) = mailbox.Message
           input: type(phish) = mailbox.Message
           return: phish. """
        return
                          
    def extract_from(self, msg):
        return msg["From"]

    def make_phish(self):
        has_sender = None
        random_msg = None
        random_from = None
        while not has_sender:
            random_msg = self.inbox[randint(0, len(self.inbox)-1)]
            random_from = self.inbox[randint(0, len(self.inbox)-1)]
            has_sender = self.extract_from(random_from)
            
        phish = mailbox.mboxMessage()
        phish['From'] = random_from['From']
        phish['To'] = random_from['To']
        phish['Subject'] = random_msg['Subject'] 
        phish = self.modify_phish(phish, random_msg)
        phish.set_payload("This is the body for a generated phishing email.\n")
        return phish
    
    def run_trials(self, num_trials=1000):
        self.detected = 0
        for i in range(num_trials):
            phish = self.make_phish()
            if self.classify(phish):
                self.detected += 1
        return self.detected / num_trials * 100




        



