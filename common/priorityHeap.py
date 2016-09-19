import heapq

class PriorityQueue:
    def __init__(self):
        self._queue = []
        self._size = 0
        self._index = 0

    def getLength(self):
        return self._size

    # returns the popped item
    # returns None if no item is popped off
    def push(self, item, priority):
        # maintains the queue to have 10 elements or less
        # element with lowest priority gets popped off
        # in this case, the element with the lowest probability gets popped off
        if self._size >= 10:
            popped = heapq.heappushpop(self._queue, (priority, self._index, item))
            self._index += 1
            return popped
        else:
            heapq.heappush(self._queue, (priority, self._index, item))
            self._size += 1
            self._index += 1
            return None

    # elements with a lower probability get popped off first
    def pop(self):
        self._size -= 1
        return heapq.heappop(self._queue)[-1]
