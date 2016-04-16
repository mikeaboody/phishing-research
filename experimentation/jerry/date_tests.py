import unittest
from date_att import *

class TestDateAtt(unittest.TestCase):
    
    def test_zeros_seen(self):
        data = DateData()
        data.process_date("Wed, 18 Mar 2015 09:50:45 +0000 (UTC)")
        self.assertEqual(data.num_detections, 0)
        data.process_date("Wed, 19 Mar 2015 09:50:45 +0000 (UTC)")
        self.assertEqual(data.num_detections, 0)
        data.process_date("Wed, 9 Mar 2015 09:50:45 +0000 (UTC)")
        self.assertEqual(data.num_detections, 0)
        data.process_date("Wed, 29 Mar 2015 09:50:45 +0000 (UTC)")
        self.assertEqual(data.num_detections, 0)
        data.process_date("Wed, 09 Mar 2015 09:50:45 +0000 (UTC)")
        self.assertEqual(data.num_detections, 1)
        data.process_date("Wed, 9 Jan 2015 09:50:45 +0000 (UTC)")
        self.assertEqual(data.num_detections, 1)
        data.process_date("Wed, 19 Jan 2015 09:50:45 +0000 (UTC)")
        self.assertEqual(data.num_detections, 1)

    def test_formats(self):
        data = DateData()
        data.process_date("Wed, 18 Mar 2015 09:50:45 +0000 (UTC)")
        self.assertEqual(data.num_detections, 0)
        data.process_date("Wed, 18 Mar 2015 09:50:45 +0000")
        self.assertEqual(data.num_detections, 1)
        data.process_date("Wed, 14 May 2015 09:50:46 +0000")
        self.assertEqual(data.num_detections, 1)
        data.process_date("Date: Thu, 08 Jul 2010 23:55:59 +0800")
        self.assertEqual(data.num_detections, 2)

if __name__ == '__main__':
    unittest.main()

