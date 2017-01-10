from __future__ import division
from detector import Detector
import functools
import editdistance
import logging
import logs
from edbag import EDBag

class Profile(object):
    """For each email, we extract the order in which the headers appeared;
       this keeps track of all of the header-orders seen in any email from
       a particular sender."""
    def __init__(self):
        self.num_emails = 0
        self.orderings = EDBag()

    def add_order(self, order):
        self.orderings.add(order)
        self.num_emails += 1

    def closest(self, order):
        return self.orderings.closest_by_edit_distance(order)

class OrderOfHeaderDetector(Detector):
    NUM_HEURISTICS = 3
    def __init__(self, inbox):
        self.inbox = inbox
        self.threshold = 7
        self.num_header = 1
        self.emails_with_sender = 0
        self.sender_profile = {}

    def modify_phish(self, phish, msg):
        return phish

    def classify(self, phish):
        sender = self.extract_from(phish)
        ordering = self.find_ordering(phish)
        if not sender in self.sender_profile:
            return [0, 0, 0]

        _, distance = self.sender_profile[sender].closest(ordering)
        detect = [1, 0, 0]
        if distance <= self.threshold:
            detect[0] = 0
        detect[1] = self.sender_profile[sender].num_emails
        detect[2] = len(self.sender_profile[sender].orderings)
        return detect

    def find_ordering(self, msg):
        """ Finds header ordering from a given email message. """
        order = []
        prev = None
        for hdr in msg.keys():
            # was: curr = intern(self.modify_header(hdr).lower())
            curr = intern(hdr.split('-')[0].lower())
            if curr != prev:
                order.append(curr)
            prev = curr
        return tuple(order)

    def modify_header(self, header):
        """ Truncates header name. """
        ## Case 1: use entire header
        #if self.num_header > 3:
        #    return header
        ## Case 2: truncate after first dash
        #parts = header.split("-", 4)
        #if self.num_header == 1:
        #    return parts[0]
        ## Case 3: truncate after second dash
        #if self.num_header == 2:
        #    if len(parts) == 1:
        #        return parts[0]
        #else:
        #    return parts[0] + "-" + parts[1]
        res = ""
        parts = header.split("-")
        for i in range(self.num_header):
            if i > len(parts) - 1:
                break
            res += parts[i] + "-"
        return res[:-1]

    def update_sender_profile(self, msg):
        sender = self.extract_from(msg)
        if sender:
            if sender not in self.sender_profile:
                self.sender_profile[sender] = Profile()
            order = self.find_ordering(msg)
            self.sender_profile[sender].add_order(order)
            self.emails_with_sender += 1

    def create_sender_profile(self, num_samples):
        for i in range(num_samples):
            email = self.inbox[i]
            self.update_sender_profile(email)
        self._debug_large_senders()

    def _debug_large_senders(self):
        nords = 0
        for sender, prof in self.sender_profile.items():
            nords = max(nords, len(prof.orderings))
        if nords > 256:
            debug_logger = logging.getLogger('spear_phishing.debug')
            debug_logger.info('Large number of orderings ({}) for sender, emails_with_sender={}; {}'.format(nords, self.emails_with_sender, logs.context))

    def trim_distributions(self, distr):
        while distr[len(distr)-1] == 0:
            distr = distr[:len(distr)-1]
        return distr

    def interesting_stats(self):
        ordering_used = [0]*20
        for ordering in self.sender_profile.values():
            num_orders = len(ordering.orderings) - 1
            total_len = len(ordering_used)
            if num_orders >= total_len:
                ordering_used.extend([0] * (num_orders - total_len + 1))
            ordering_used[num_orders] += 1
        ordering_used = self.trim_distributions(ordering_used)
        self.ordering_used = ordering_used
        print(ordering_used)

        uniqueSenders = len(self.sender_profile)
        total_emails = len(self.inbox)
        four = (functools.reduce(lambda x, y : x + y, self.ordering_used[:4])) / uniqueSenders * 100
        print("Total emails = " + str(total_emails))
        print("Emails with sender = " + str(self.emails_with_sender))
        print("unique Senders = " + str(uniqueSenders))
        print("distribution_of_num_ordering_used = " + str(self.ordering_used))
        # print("false alarm rate ordering format = %.2f percent" % (self.falsies))
        print("percent of senders with <=4 ordering formats used = %.3f" % (four))
