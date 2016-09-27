import bisect

class PriorityQueue:
    def __init__(self):
        # self._queue has a tuple with three values: (priority, self._id, and item)
        # The priority is the probability and the item is an email represented by a numpy array
        self._queue = []
        self._size = 0
        self._id = 0

        # a unique sender is determined by the path to the sender's emails
        self._uniqueSenders = set([])

    def getLength(self):
        return self._size


    # adds item to priority queue if among the top 10 emails with highest priority
    # only one email is maintained in the priority queue per sender
    def push(self, item, priority):
        # checks to see if this sender is already in that priority queue
        # if so, checks to see if probability should be updated
        thisSender = item[0]
        if thisSender in self._uniqueSenders:
            senderIndex = None
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

        # maintains the queue to have 10 elements or less
        if self._size > 10:
            popped = self._queue.pop(0)
            self._uniqueSenders.remove(popped[2][0])
            self._size -= 1

    # elements with a higher probability get popped off first
    def pop(self):
        self._size -= 1
        return self._queue.pop()

    def createOutput(self):
        results = []
        for item in self._queue[::-1]:
            currentItem = item[2].tolist()
            with open(currentItem[0]) as fp:
                for i, line in enumerate(fp):
                    if i == int(currentItem[1]):
                        currentItem.append(line)
                        break
            results.append(currentItem)
        return results

    def __str__(self):
        return str(self._queue)

    def __repr__(self):
        return str(self._queue)
