from collections import Counter
import editdistance
from repoze.lru import LRUCache

"""A bag (multiset) of tuples, supporting edit distance operations over 
   its elements and a count of the number of times each element occurs.
   Supports the interface of Counter.  Each element should be a
   tuple (or other hashable sequence)."""
class EDBag(Counter):
    cache1 = LRUCache(256) # values where distance=1
    cache2 = LRUCache(256) # values where distance>1

    def add(self, x):
        if not x in self:
            self.cache2.clear()
        self[x] += 1

    def closest_by_edit_distance(self, x):
        if x in self:
            # Optimization: if x is in multiset, then closest
            # edit dist = 0. Nothing can be any closer.
            return (x, 0)

        # Optimization: If we've looked up this value before, 
        # return previously computed answer.
        cached_answer = self.cache1.get(x)
        if cached_answer:
            return cached_answer
        cached_answer = self.cache2.get(x)
        if cached_answer:
            return cached_answer

        closest = None
        closest_dist = None
        for y,_ in self.most_common():
            d = editdistance.eval(x, y)
            if not closest_dist or d < closest_dist:
                closest = y
                closest_dist = d
                if d == 1:
                    # Optimization: nothing can be any closer, as
                    # we know there's nothing at edit distance 0 (x is not
                    # in the multiset).
                    self.cache1.put(x, (closest, closest_dist))
                    return (closest, closest_dist)

        self.cache2.put(x, (closest, closest_dist))
        return (closest, closest_dist)
