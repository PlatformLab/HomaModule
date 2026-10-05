#!/usr/bin/env python3
# Unit-test UDP pacing rate summaries and acceptance limits
# using synthetic timestamped traffic samples.

import unittest

import verify_udp_pacing


class VerifyUdpPacingTest(unittest.TestCase):
    def test_rate_summary(self):
        samples = [(index / 1000, 12500) for index in range(1000)]

        summary = verify_udp_pacing.rate_summary(samples)

        self.assertGreaterEqual(summary["steady_mbps"], 99)
        self.assertLessEqual(summary["steady_mbps"], 101)
        self.assertGreaterEqual(summary["max_100ms_mbps"], 99)
        self.assertLessEqual(summary["max_100ms_mbps"], 101)

    def test_short_capture_rejected(self):
        with self.assertRaisesRegex(ValueError, "too short"):
            verify_udp_pacing.rate_summary([(0, 100), (0.1, 100)])


if __name__ == "__main__":
    unittest.main()
