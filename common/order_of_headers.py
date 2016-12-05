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

class Profile(object):
    num_emails = 0
    formats = EDBag()

    def add_format(self, format):
        self.formats.add(format)
        self.num_emails += 1

    def closest(self, format):
        return self.formats.closest_by_edit_distance(format)

class OrderOfHeaderDetector(Detector):
    NUM_HEURISTICS = 3
    def __init__(self, inbox):
        self.inbox = inbox
        self.threshold = 7
        self.num_header = 1

    def modify_phish(self, phish, msg):
        return phish

    def edit_distance_thresh(self, orig, curr):
        """Returns True if ORIG and CURR are <= self.threshold edit
           distance apart. Assumes ORIG has been converted to a list,
           and CURR has not been. """
        diff = editdistance.eval(orig, curr)
        if diff <= self.threshold:
            return True
        return False

    def classify(self, phish):
        # total, emails, editdistance
        sender = self.extract_from(phish)
        detect = [1, 0, 0]
        ordering = self.find_ordering(phish, error=False)
        if sender in self.sender_profile:
            _, distance = self.sender_profile[sender].closest(ordering)
            if distance <= self.threshold:
                detect[0] = 0
            detect[1] = self.sender_profile[sender].num_emails
            detect[2] = len(self.sender_profile[sender].formats)
        else:
            detect[0] = 0
        return detect

    def update_sender_profile(self, value, sender):
        if sender not in self.sender_profile:
            self.sender_profile[sender] = Profile()
        self.sender_profile[sender].add_format(value)

    def update_entire_attribute(self, value):
        if value not in self.entire_attribute:
            self.entire_attribute[value] = 1
        else:
            self.entire_attribute[value] += 1

    def find_ordering_real(self, msg, name=False):
        """ Finds named header ordering from a given MSG. """
        order = ""
        for i, k in enumerate(msg.keys()):
            k = k.lower()
            if k not in self.header_map:
                self.header_map[k] = len(self.header_map)
            curr = self.header_map[k]
            if name:
                curr = k
            order += (str(curr) + " ")
        order = order[:-1]
        return order


    def find_ordering(self, msg, error=False):
        """ Finds numbered header ordering from a given MSG. """
        order = []
        prev = None
        for i, k in enumerate(msg.keys()):
            k = self.modify_header(k.lower())
            if k not in self.header_map:
                self.header_map[k] = len(self.header_map)
                if error is True:
                    print(curr_len)
                    print(k)
                    print(i)
                    raise Exception("could not find header in map")
            curr = self.header_map[k]
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

    def ordering_to_name(self, ordering):
        """ Takes ordering number string and converts to header name. """
        named_order = ""
        ind_to_name = {v: k for k, v in self.header_map.items()}
        for n in ordering:
            named_order += ind_to_name[n] + " "
        return named_order

    def print_header_mapping(self):
        """ Prints mapping from index to header. """
        ind_to_name = {v: k for k, v in self.header_map.items()}
        pprint.pprint(ind_to_name)

    def create_sender_profile(self, num_samples):
        self.emails_with_sender = 0
        self.sender_profile = {}
        self.header_map = {}
        self.entire_attribute = {}
        self.full_order = {}
        avg_length = 0
        for i in range(num_samples):
            msg = self.inbox[i]
            sender = self.extract_from(msg)
            if sender:
                order = self.find_ordering(msg)
                named_order = self.ordering_to_name(order)
                length = len(order)
                avg_length += length
                if named_order not in self.full_order:
                    self.full_order[named_order] = 1
                else:
                    self.full_order[named_order] += 1
                self.update_sender_profile(order, sender)
                self.emails_with_sender += 1
                self.update_entire_attribute(order)
        self._debug_large_senders()


    def _debug_large_senders(self):
        nords = 0
        for sender, prof in self.sender_profile.items():
            nords = max(nords, len(prof.formats))
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
            for ordering in self.sender_profile[sender].formats:
                num = len(ordering.split(" "))
                if num not in len_ordering[sender]:
                    len_ordering[sender][num] = 1
                else:
                    len_ordering[sender][num] += 1
                count += 1
        # key: diff val: number of times I've seen
        count_diff = {}
        for sender, profile in self.sender_profile.items():
            ordering = profile.formats
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
            num_formats = len(ordering.formats) - 1
            total_len = len(ordering_used)
            if num_formats >= total_len:
                ordering_used.extend([0] * (num_formats - total_len + 1))
            ordering_used[num_formats] += 1
        ordering_used = self.trim_distributions(ordering_used)
        self.ordering_used = ordering_used
        #pprint.pprint(self.header_map)
        print("Length of map = " + str(len(self.header_map)))
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

