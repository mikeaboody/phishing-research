from sys import argv
import mailbox
import pylab as pl
import numpy as np
import re
import random
import detector


class ContentTransferEncodingDetector(detector.Detector):

    def __init__(self, inbox):
        self.inbox = inbox
        print("Creating sender profile...")
        self.create_sender_profile()
        print("Done.")
        print("Running trials...")
        print(self.run_trials(1000))
        print("Done.")

    def create_sender_profile(self):
        self.sender_profile = {}
        for i in range(len(self.inbox)):
            msg = self.inbox[i]
            curr_sender = self.extract_from(msg)
            if curr_sender:
                # per sender
                curr_profile = self.sender_profile.get(curr_sender, set())
                curr_cte = getCTE(msg)
                similar_cte = getSimilar(curr_cte, curr_profile)
                if similar_cte == False:
                    curr_profile.add(curr_cte)
                self.sender_profile[curr_sender] = curr_profile
        count = 0
    def classify(self, phish):
        curr_sender = self.extract_from(phish)
        curr_cte = getCTE(phish)
        curr_profile = self.sender_profile.get(curr_sender, None)
        if not curr_profile:
            return False
        similar_cte = getSimilar(curr_cte, curr_profile)
        return similar_cte == False
    def modify_phish(self, phish, msg):
        phish["Content-Transfer-Encoding"] = msg["Content-Transfer-Encoding"]
        return phish



def getCTE(msg):
    cte = msg["Content-Transfer-Encoding"]
    return cte

def getSimilar(given_str, given_set):
    for s in given_set:
        # if s and given_str and Levenshtein.ratio(given_str, s) > 0.9:
        if (not s and not given_str) or (s and given_str and given_str.lower() == s.lower()):
            return s
    return False

file_name = "/Volumes/HP c310w/" + argv[1]
box = mailbox.mbox(file_name + ".mbox")
cte_detector = ContentTransferEncodingDetector(box)

# content_type_to_cte = {}

# for msg in box:
#     curr_content_type = msg["Content-Type"]
#     curr_transfer_encoding = msg["Content-Transfer-Encoding"]
#     curr_profile = content_type_to_cte.get(curr_content_type, set())
#     if getSimilar(curr_transfer_encoding, curr_profile) == False:
#         curr_profile.add(curr_transfer_encoding)
#     content_type_to_cte[curr_content_type] = curr_profile

# count = 0
# ones = {}
# for ct in content_type_to_cte:
#     if len(content_type_to_cte[ct]) >= 2:
#         count += 1
#         ones[ct] = content_type_to_cte[ct]

# import pdb; pdb.set_trace()
# print(count)


#content-transfer-encoding
#berkeley.edu: 20.3%
#gmail.com: 12.1%
