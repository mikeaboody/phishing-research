import logs
from detector import Detector

class MessageIdFormatDetector(Detector):
    DELIMITERS = ['.', '-', '$', '/', '%']
    NUM_HEURISTICS = 2

    def __init__(self, regular_mbox):
        self.inbox = regular_mbox

    def most_common_delimiter(self, uid):
        highest_count = 0
        for delimiter in self.DELIMITERS:
            delim_count = uid.count(delimiter)
            if delim_count > highest_count:
                highest_count = delim_count
                freq_delim = delimiter
        if highest_count == 0:
            return None, 0
        else:
            return freq_delim, highest_count

    def partition_within_error(self, features, new_feature, fudge_factor=0):
        for old_feature in features:
            if old_feature[0] != new_feature[0] or old_feature[1] != new_feature[1]:
                continue
            old_partition_sizes = old_feature[2].split(' ')
            new_partition_sizes = new_feature[2].split(' ')
            old_sum = sum([int(x) for x in old_partition_sizes])
            new_sum = sum([int(x) for x in new_partition_sizes])
            if abs(old_sum - new_sum) <= fudge_factor:
                return True
        return False

    def partition_length(self, uid, delimiter, count):
        if count == 0:
            return str(len(uid))
        split_uid = uid.split(delimiter)
        return " ".join([str(len(split)) for split in split_uid])

    def create_sender_profile(self, num_samples):
        self.sender_profile = {}
        self.sender_count = {}
        for i in range(num_samples):
            msg = self.inbox[i]
            sender = self.extract_from(msg)
            message_id = msg["Message-ID"]
            if message_id == None:
                logs.RateLimitedLog.log("No message ID found, during create_sender_profile().")
                continue
            split_msg_id = message_id.split('@')
            if len(split_msg_id) < 2:
                logs.RateLimitedLog.log("Message-ID misformatted", private=message_id)
                continue
            domain = split_msg_id[1][:-1]
            uid = split_msg_id[0][1:]
            common_delimiter, delimiter_count = self.most_common_delimiter(uid)
            partition_sizes = self.partition_length(uid, common_delimiter, delimiter_count)
            features = (common_delimiter, delimiter_count, partition_sizes)
            if sender in self.sender_profile:
                is_valid = self.partition_within_error(self.sender_profile[sender], features, fudge_factor=2)
                if not is_valid:
                    self.sender_profile[sender].add(features)
                self.sender_count[sender] += 1
            else:
                self.sender_profile[sender] = set([features])
                self.sender_count[sender] = 1
        return self.sender_profile

    def classify(self, phish):
        sender = self.extract_from(phish)
        message_id = phish["Message-ID"]
        if message_id == None:
            logs.RateLimitedLog.log("No message ID found, during classify().")
            return [0.0, 0.0]
        split_msg_id = message_id.split('@')
        if len(split_msg_id) < 2:
            logs.RateLimitedLog.log("Message-ID misformatted", private=message_id)
            return [0.0, 0.0]
        domain = split_msg_id[1][:-1]
        uid = split_msg_id[0][1:]
        common_delimiter, delimiter_count = self.most_common_delimiter(uid)
        partition_sizes = self.partition_length(uid, common_delimiter, delimiter_count)
        features = (common_delimiter, delimiter_count, partition_sizes)
        if sender in self.sender_profile:
            is_valid = self.partition_within_error(self.sender_profile[sender], features, fudge_factor=0)
            h1 = float(not is_valid)
            h2 = -self.sender_count[sender] if is_valid else self.sender_count[sender]
            return [h1, h2]
        else:
            return [0.0, 0.0]

    def modify_phish(self, phish, msg):
        phish['Message-ID'] = msg['Message-ID']
        return phish

class MessageIdDetectorTwo(MessageIdDetectorOne):
    def create_sender_profile(self, num_samples):
        self.sender_profile = {}
        for i in range(num_samples):
            msg = self.inbox[i]
            sender = self.extract_from(msg)
            message_id = msg["Message-ID"]
            split_msg_id = message_id.split('@')
            if len(split_msg_id) < 2:
                print("Message-ID misformatted: {}".format(message_id))
                continue
            domain = split_msg_id[1][:-1]
            uid = split_msg_id[0][1:]
            common_delimiter, delimiter_count = self.most_common_delimiter(uid)
            partition_sizes = self.partition_length(uid, common_delimiter, delimiter_count)
            features = (common_delimiter, delimiter_count, partition_sizes)
            if sender in self.sender_profile:
                is_valid = self.partition_within_error(self.sender_profile[sender], features, fudge_factor=2)
                if not is_valid:
                    self.sender_profile[sender].add(features)
            else:
                self.sender_profile[sender] = set([features])
        return self.sender_profile
