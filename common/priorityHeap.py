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

## main
# q = PriorityQueue()
# q.push("Six", 6)
# q.push("Seven", 7)
# q.push("Eight", 8)
# q.push("Nine", 9)
# q.push("Ten", 10)
# q.push("One", 1)
# q.push("Two", 2)
# q.push("Three", 3)
# q.push("Four", 4)
# q.push("Five", 5)
