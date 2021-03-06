import bisect

class PriorityQueue:
    def __init__(self, maxQueueSize):
        # self._queue has a tuple with three values: (priority, self._id, and ResultRecord)
        # The priority is the probability and the item is an email represented by a numpy array
        self._queue = []
        self._size = 0
        self._id = 0
	self.MAX_SIZE = maxQueueSize 
	

        # a unique sender is determined by the path to the sender's emails

    def getLength(self):
        return self._size


    # adds item to priority queue if among the top 10 emails with highest priority
    # only one email is maintained in the priority queue per sender
    def push(self, record, priority):
        bisect.insort_left(self._queue,(priority, self._id, record))
        self._id += 1
        self._size += 1

        # maintains the queue to have 10 elements or less
        if self._size > self.MAX_SIZE:
            popped = self._queue.pop(0)
            self._size -= 1

    # elements with a higher probability get popped off first
    def pop(self):
        self._size -= 1
        return self._queue.pop()

    def createOutput(self):
        results = []
        for item in self._queue[::-1]:
            record = item[2]
            results.append(record)
        return results

    def __str__(self):
        return str(self._queue)

    def __repr__(self):
        return str(self._queue)
