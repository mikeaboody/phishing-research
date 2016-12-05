from __future__ import division
from detector import Detector
import re
import functools
import pprint
from random import randint
import sys
import numpy as np
import editdistance
import logging
from edbag import EDBag

"""For each email, we extract the order in which the headers appeared;
   this keeps track of all of the header-orders seen in any email from
   a particular sender."""
class Profile(object):
    num_emails = 0
    orderings = EDBag()

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

    def modify_phish(self, phish, msg):
        return phish

    def classify(self, phish):
        sender = self.extract_from(phish)
        detect = [1, 0, 0]
        ordering = self.find_ordering(phish)
        if sender in self.sender_profile:
            _, distance = self.sender_profile[sender].closest(ordering)
            if distance <= self.threshold:
                detect[0] = 0
            detect[1] = self.sender_profile[sender].num_emails
            detect[2] = len(self.sender_profile[sender].orderings)
        else:
            detect[0] = 0
        return detect

    def update_sender_profile(self, value, sender):
        if sender not in self.sender_profile:
            self.sender_profile[sender] = Profile()
        self.sender_profile[sender].add_order(value)

    def update_entire_attribute(self, value):
        if value not in self.entire_attribute:
            self.entire_attribute[value] = 1
        else:
            self.entire_attribute[value] += 1

    def find_ordering(self, msg):
        """ Finds numbered header ordering from a given MSG. """
        order = []
        prev = None
        for hdr in msg.keys():
            curr = self.modify_header(hdr.lower())
            if curr != prev:
                order.append(curr)
            prev = curr
        return tuple(order)

    def modify_header(self, header):
        """ Edits header name before lookup/adding in header map. 
            Truncation happens here. """
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

    def create_sender_profile(self, num_samples):
        self.emails_with_sender = 0
        self.sender_profile = {}
        self.entire_attribute = {}
        avg_length = 0
        for i in range(num_samples):
            msg = self.inbox[i]
            sender = self.extract_from(msg)
            if sender:
                order = self.find_ordering(msg)
                length = len(order)
                avg_length += length
                self.update_sender_profile(order, sender)
                self.emails_with_sender += 1
                self.update_entire_attribute(order)
        self._debug_large_senders()

    def _debug_large_senders(self):
        nords = 0
        for sender, prof in self.sender_profile.items():
            nords = max(nords, len(prof.orderings))
        if nords > 256:
            debug_logger = logging.getLogger('spear_phishing.debug')
            debug_logger.info('Large number of orderings ({}) for sender; {}'.format(nords, logs.context))

    def trim_distributions(self, distr):
        while distr[len(distr)-1] == 0:
            distr = distr[:len(distr)-1]
        return distr

    def analyzing_sender_profile(self):
        len_ordering = {}
        count = 1
        for sender in self.sender_profile:
            len_ordering[sender] = {}
            for ordering in self.sender_profile[sender].orderings:
                num = len(ordering.split(" "))
                if num not in len_ordering[sender]:
                    len_ordering[sender][num] = 1
                else:
                    len_ordering[sender][num] += 1
                count += 1
        # key: diff val: number of times I've seen
        count_diff = {}
        for sender, profile in self.sender_profile.items():
            ordering = profile.orderings
            if len(ordering) > 1:
                one = list(ordering)[0].split(" ")
                two = list(ordering)[1].split(" ")
                count_diff = self.add_dict(count_diff, int(editdistance.eval(one, two)))
        #pprint.pprint(len_ordering)

    def add_dict(self, d, k):
        if k not in d:
            d[k] = 1
        else:
            d[k] += 1
        return d

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
