import unittest
from timezone import *

class TestTimezone(unittest.TestCase):
    
    def test_timezones(self):
        data = DateData()
        data.process_timezone("Wed, 18 Mar 2015 09:50:45 +0000 (UTC)")
        self.assertEqual(data.num_detections, 0)
        data.process_timezone("Wed, 18 Mar 2015 09:50:45 +0000")
        self.assertEqual(data.num_detections, 0)
        data.process_timezone("Wed, 14 May 2015 09:50:46 +1000")
        self.assertEqual(data.num_detections, 1)
        data.process_timezone("Date: Thu, 08 Jul 2010 23:55:59 +0800")
        self.assertEqual(data.num_detections, 2)

if __name__ == '__main__':
    unittest.main()

