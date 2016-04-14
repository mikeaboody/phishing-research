from __future__ import division
from detector import Detector
import mailbox
import re
import functools
import pprint
from random import randint
import sys
import matplotlib.pyplot as plt
import numpy as np
from Levenshtein import distance
import editdistance

class Content_Type_Detector(Detector):
    def __init__(self, inbox, num_header, threshold):
        self.inbox = inbox
        self.threshold = threshold
        self.num_header = num_header
        self.create_sender_profile()
        # [content-type, charset, boundary]
        self.detections = {"content-type": 0, "charset": 0, "boundary": 0}

    def modify_phish(self, phish, msg):
        # need to fix detector class. Should just return a random msg with random
        # from header. this is hack, change it.
        #msg['From'] = phish['From']
        #print(phish['From'])
        #print(self.find_ordering(phish))
        #print(self.find_ordering(msg))
        #print(msg['From'])
        return msg

    def clean_spaces(self, text):
        return text.strip(" \t\r\n")

    def has_quotes(self, text):
        return re.match("\".*\"", text) is not None

    def strip_quotes(self, text):
        if self.has_quotes(text):
            return text[1:len(text) - 1]
        return text
        
    def edit_distance_thresh(self, orig, curr):
        """Returns True if ORIG and CURR are <= self.threshold edit
           distance apart. Assumes ORIG has been converted to a list,
           and CURR has not been. """
        curr = self.convert_to_list(curr)
        diff = editdistance.eval(orig, curr)
        if diff <= self.threshold:
            return True
        return False

    def classify(self, phish):
        sender = self.extract_from(phish)
        sender = self.inbox[randint(0, len(self.inbox)-1)]['From']
        ordering = self.find_ordering(phish, error=True)
        new_val = self.convert_to_list(ordering)
        phishy = True
        if sender in self.sender_profile.keys():
            for o in list(self.sender_profile[sender]):
                if self.edit_distance_thresh(new_val, o):
                    phishy = False
                    break
        else:
            print("Sender was not found in sender_profile: %s" % (sender))
        return phishy

    def convert_to_list(self, ordering):
        return ordering.split(" ")

    def update_sender_profile(self, value, sender):
        new_format = 1
        if sender not in self.sender_profile.keys():
            self.sender_profile[sender] = set([value])
            new_format = 0
        else:
            seen = list(self.sender_profile[sender])
            new_val = self.convert_to_list(value)
            for ordering in seen:
                if self.edit_distance_thresh(new_val, ordering):
                    new_format = 0
                    break
        #if value not in self.sender_profile[sender]:
        #    new_format = 1
        self.sender_profile[sender].add(value)
        return new_format

    def update_entire_attribute(self, value):
        if value not in self.entire_attribute.keys():
            self.entire_attribute[value] = 1
        else:
            self.entire_attribute[value] += 1

    def graph_distribution(self):
        self.ordering_used.insert(0, 0)
        plt.plot([x for x in range(len(self.ordering_used))], self.ordering_used, 'bo', markersize=8)
        plt.xlabel("Total number of Orderings used")
        plt.ylabel("Number of Senders")
        plt.title("Distribution of Ordering Formats used across Senders")
        plt.show() 
        return

    def find_ordering_real(self, msg, name=False):
        """ Finds named header ordering from a given MSG. """
        order = ""
        for i, k in enumerate(msg.keys()):
            k = k.lower()
            if k not in self.header_map.keys():
                self.header_map[k] = len(self.header_map)
            curr = self.header_map[k]
            if name:
                curr = k
            order += (str(curr) + " ")
        order = order[:-1]
        return order


    def find_ordering(self, msg, error=False):
        """ Finds numbered header ordering from a given MSG. """
        order = ""
        prev = None
        curr_len = 0
        for i, k in enumerate(msg.keys()):
            # cutoff
            #if curr_len == 10:
            #    break
            k = self.modify_header(k.lower())
            if k not in self.header_map.keys():
                self.header_map[k] = len(self.header_map)
                if error is True:
                    print(curr_len)
                    print(k)
                    print(i)
                    raise Exception("could not find header in map")
            curr = self.header_map[k]
            if curr != prev:
                order += (str(curr) + " ")
                curr_len += 1
            prev = curr
        order = order[:-1]
        return order

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
        ind = ordering.split(" ")
        ind_to_name = {v: k for k, v in self.header_map.items()}
        for x in ind:
            n = int(x)
            named_order += ind_to_name[n] + " "
        return named_order

    def print_header_mapping(self):
        """ Prints mapping from index to header. """
        ind_to_name = {v: k for k, v in self.header_map.items()}
        pprint.pprint(ind_to_name)

    def create_sender_profile(self):
        self.emails_with_sender = 0
        self.sender_profile = {}
        self.header_map = {}
        self.false_alarms = 0
        self.entire_attribute = {}
        self.full_order = {}
        self.sender_to_newformat = {}
        avg_length = 0
        for msg in self.inbox:
            sender = self.extract_from(msg)
            if sender:
                order = self.find_ordering(msg)
                named_order = self.ordering_to_name(order)
                length = len(self.convert_to_list(order))
                avg_length += length
                if named_order not in self.full_order.keys():
                    self.full_order[named_order] = 1
                else:
                    self.full_order[named_order] += 1
                new = self.update_sender_profile(order, sender)
                self.sender_to_newformat[sender] = 0
                if new == 1:
                    self.sender_to_newformat[sender] += 1
                self.false_alarms += new
                self.emails_with_sender += 1
                self.update_entire_attribute(order)

        print_order = sorted( ((v, k) for k, v in self.entire_attribute.items()), reverse=True)
        print_named_order = sorted( ((v, k) for k, v in self.full_order.items()), reverse=True)
        print("Avg number of headers = %d" % (avg_length / self.emails_with_sender))
        self.falsies = self.false_alarms / self.emails_with_sender * 100

        #printing all
       # for k, v in print_order:
       #     print("%d: %s" % (k, v))
       # for k, v in print_named_order:
       #     print("%d: %s" % (k, v))
        #printing 20 most and 20 least.
        #for k, v in print_order[:20]:
        #    print("%d: %s" % (k, v))
        #for k, v in print_order[len(self.entire_attribute) - 20:]:
        #    print("%d: %s" % (k, v))
        #print("num formats = " + str(len(self.entire_attribute)))
        #for k, v in print_named_order[:20]:
        #    print("%d: %s" % (k, v))
       ## for msg in self.inbox:
       ##     sender = self.extract_from(msg)
       ##     if sender:
       ##         for k, v in msg.items():
       ##             print("key = " + str(k) , "value = " + str(v))
       ##         print("==========^^^^===================")
       ##         printInfo(msg)
       ##         print("===========^^^^===================")
       ##         count += 1
       ##         if count == 3:
       ##             break

    def trim_distributions(self, distr):
        while distr[len(distr)-1] == 0:
            distr = distr[:len(distr)-1]
        return distr

    def analyzing_sender_profile(self):
        len_ordering = {}
        count = 1
        for sender in self.sender_profile.keys():
            len_ordering[sender] = {}
            for ordering in self.sender_profile[sender]:
                num = len(ordering.split(" "))
                if num not in len_ordering[sender].keys():
                    len_ordering[sender][num] = 1
                else:
                    len_ordering[sender][num] += 1
                count += 1
        # key: diff val: number of times I've seen
        count_diff = {}
        for sender, ordering in self.sender_profile.items():
            if len(ordering) > 1:
                one = list(ordering)[0].split(" ")
                two = list(ordering)[1].split(" ")
                count_diff = self.add_dict(count_diff, int(editdistance.eval(one, two)))
        #pprint.pprint(len_ordering)
        pprint.pprint(count_diff)

        for sender, ordering in self.sender_profile.items():
            if len(ordering) > 4:
                print(len(ordering))
                print(self.sender_to_newformat[sender])
                print("===up===")
        for sender, smt in self.sender_to_newformat.items():
            if smt > 1:
                print(smt)
                print(len(self.sender_profile[sender]))
                print("===uppp===")

    def add_dict(self, d, k):
        if k not in d.keys():
            d[k] = 1
        else:
            d[k] += 1
        return d

    def interesting_stats(self):
        ordering_used = [0]*20
        for ordering in self.sender_profile.values():
            num_formats = len(ordering) - 1
            total_len = len(ordering_used)
            if num_formats >= total_len:
                ordering_used.extend([0] * (num_formats - total_len + 1))
            ordering_used[num_formats] += 1
        ordering_used = self.trim_distributions(ordering_used)
        self.ordering_used = ordering_used
        #pprint.pprint(self.header_map)
        print("Length of map = " + str(len(self.header_map)))
        print(ordering_used)

        uniqueSenders = len(self.sender_profile.keys())
        total_emails = len(self.inbox)
        four = (functools.reduce(lambda x, y : x + y, self.ordering_used[:4])) / uniqueSenders * 100
        print("Total emails = " + str(total_emails))
        print("Emails with sender = " + str(self.emails_with_sender))
        print("unique Senders = " + str(uniqueSenders))
        print("distribution_of_num_ordering_used = " + str(self.ordering_used))
        print("false alarm rate ordering format = %.2f percent" % (self.falsies))
        print("percent of senders with <=4 ordering formats used = %.3f" % (four))

def printInfo(msg):
    print(msg["From"])
    print(msg["Content-Type"])
    print(msg["Subject"])


#file_name = "~/emails/Inbox500.mbox"
#inbox = mailbox.mbox(file_name)
#d = Content_Type_Detector(inbox, 1)
#d.interesting_stats()
#d.analyzing_sender_profile()
##d.graph_distribution()
#print("detection rate = " + str(d.run_trials()))


def graph_rate_file():
    import csv
    with open("rates_with_diff_thresh.csv", "r") as r_file:
        reader = csv.reader(r_file, delimiter=',')
        r_dict = {}
        r_list = []
        c_list = []
        for i, row in enumerate(reader):
            if i == 0:
                continue
            cond = (row[0], row[1])
            ratio = float(row[2]) / float(row[3])
            r_list.append(ratio)
            c_list.append(cond)
            r_dict[cond] = ratio
        ind = np.argmax(r_list)
        bestC = c_list[ind]
        bestR = r_list[ind]
        print(bestC)
        print(bestR)
        plt.plot([x for x in range(len(r_list))], r_list, 'bo', markersize=3)
       # plt.xlabel("Total number of Orderings used")
       # plt.ylabel("Number of Senders")
       # plt.title("Distribution of Ordering Formats used across Senders")
        plt.show() 
        
        

def write_rate_files():
    import csv
    thresh_list = [3, 5, 7, 9, 10, 12]
    num_heads = [1, 2, 3, 4, 100]
    titles = ["threshold", "header_length", "detection_rates", "falsealarm_rates"]
    with open("rates_with_diff_thresh.csv", 'w') as d_file:
            d_writer = csv.writer(d_file, delimiter=',')
            d_writer.writerow(titles)
            for thresh in thresh_list:
                for header_length in num_heads:
                    d = Content_Type_Detector(inbox, header_length, thresh)
                    detection_rate = str(d.run_trials())
                    false_alarm = d.falsies
                    print("header length = %d, threshold = %d" % (header_length, thresh))
                    print("detection rate = " + detection_rate)
                    print("false alarm rate = %.2f percent" % (false_alarm))
                    d_writer.writerow([str(thresh), str(header_length), detection_rate, str(false_alarm)])
            
file_name = "~/emails/Inbox.mbox"
#inbox = mailbox.mbox(file_name)
graph_rate_file()





"""Line 12 and 17 in rates file.
   being stricter, higher false alarm rates, higher detection
   more lax, lower false alarm, lower detection"""
