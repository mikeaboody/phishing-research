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
    def check_header(self, msg):
        """Checks if msg contains the desired email header field. ex: x-mailer.
           input: type(msg) = mailbox.Message
           return: boolean value. """
        return
    
    @abc.abstractmethod
    def modify_phish(self, phish, msg):
        """Adds the desired email header field from msg to phish.
           input: type(msg) = mailbox.Message
           input: type(phish) = mailbox.Message
           return: phish. """
        return
                          
    def length(self):
        return len(self.inbox)
   
    def extract_from(self, msg):
        from_header = msg["From"]
        if not from_header:
            return None
        from_header = from_header.lower()
        r = re.compile(" *<.*> *")
        from_header = r.sub("", from_header)
        r = re.compile("^ +")
        from_header = r.sub("", from_header)
        return from_header

    def make_phish(self):
        has_sender = None
        random_msg = None
        random_from = None
        validEmail = None
        while not has_sender or not validEmail:
            random_msg = self.inbox[randint(0, len(self.inbox)-1)]
            random_from = self.inbox[randint(0, len(self.inbox)-1)]
            has_sender = random_from["From"]
            validEmail = not ("List-Unsubscribe" in random_from.keys() or "nexusapoorvacus19@gmail.com" in random_from["From"])
            
        phish = mailbox.mboxMessage()
        phish['From'] = random_from['From']
        phish['To'] = random_msg['To']
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
        return self.detected*1.0 / num_trials * 100.0




        



