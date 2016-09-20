import bisect

class PriorityQueue:
    def __init__(self):
        self._queue = []
        self._size = 0
        self._id = 0

        # a unique sender is determined by the path to the sender's emails
        self._uniqueSenders = set([])

    def getLength(self):
        return self._size

    # returns the popped item
    # returns None if no item is popped off
    def push(self, item, priority):
        # maintains the queue to have 10 elements or less
        # element with lowest priority gets popped off
        # in this case, the element with the lowest probability gets popped off

        # checks to see if this sender is already in that priority queue
        # if so, checks to see if probability should be updated
        thisSender = item[0]
        if thisSender in self._uniqueSenders:
            senderIndex = 0
            for i in range(len(self._queue)):
                if self._queue[i][2][0] == thisSender:
                    senderIndex = i
            if self._queue[senderIndex][0] < priority:
                # update the priority of this item in the priority queue
                self._queue.pop(senderIndex)
                bisect.insort_left(self._queue,(priority, self._id, item))
                self._id += 1
            return

        # sender is not in priority queue
        bisect.insort_left(self._queue,(priority, self._id, item))
        self._id += 1
        self._uniqueSenders.add(item[0])
        self._size += 1

        if self._size > 10:
            popped = self._queue.pop(0)
            self._uniqueSenders.remove(popped[2][0])
            self._size -= 1
            return popped

    # elements with a higher probability get popped off first
    def pop(self):
        self._size -= 1
        return self._queue.pop()

    def createOutput(self):
        results = []
        for item in self._queue[::-1]:
            results.append(item[2].tolist())
        return results

    def __str__(self):
        return str(self._queue)

    def __repr__(self):
        return str(self._queue)

# main
# pq = PriorityQueue()
# pq.push(["hi7", 7], 7)
# pq.push(["hi8", 8], 8)
# pq.push(["hi9", 9], 9)
# pq.push(["hi10", 10], 10)
# pq.push(["hi11", 11], 11)
# pq.push(["hi1", 1], 1)
# pq.push(["hi2", 2], 2)
# pq.push(["hi3", 3], 3)
# pq.push(["hi4", 4], 4)
# pq.push(["hi5", 5], 5)
# pq.push(["hi6", 6], 6)
