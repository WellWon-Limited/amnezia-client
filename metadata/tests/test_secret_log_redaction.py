from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class SecretLogRedactionTests(unittest.TestCase):
    def test_ios_push_log_never_contains_the_apns_token(self) -> None:
        source = (ROOT / "client/platforms/ios/AvpnPushController.mm").read_text(
            encoding="utf-8"
        )
        self.assertNotIn('APNs device token (%@): %@', source)
        self.assertIn('APNs device token registered (%@, %lu bytes)', source)

    def test_ios_openvpn_log_never_contains_a_payload_preview(self) -> None:
        source = (ROOT / "client/platforms/ios/ios_controller.mm").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("payloadPreview", source)
        self.assertIn('<< "ovpnBytes="', source)


if __name__ == "__main__":
    unittest.main()
