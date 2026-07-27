from __future__ import annotations

import unittest

from pi_circle.api_response import failure, success


class ApiResponseTests(unittest.TestCase):
    def test_success_envelope(self) -> None:
        payload = success({"answer": 42})

        self.assertTrue(payload["ok"])
        self.assertEqual(payload["data"], {"answer": 42})
        self.assertIsNone(payload["error"])
        self.assertTrue(str(payload["timestamp"]).endswith("Z"))

    def test_failure_envelope(self) -> None:
        payload = failure("PIHOLE_UNAVAILABLE", "Pi-hole is not responding.", {"service": "pihole-FTL"})

        self.assertFalse(payload["ok"])
        self.assertIsNone(payload["data"])
        self.assertEqual(payload["error"]["code"], "PIHOLE_UNAVAILABLE")
        self.assertEqual(payload["error"]["details"], {"service": "pihole-FTL"})


if __name__ == "__main__":
    unittest.main()
