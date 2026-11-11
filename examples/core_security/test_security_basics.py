import unittest

from security_basics import authorize, sign_message, verify_message


class AuthorizationTests(unittest.TestCase):
    def test_allowed_role_action_resource(self):
        self.assertTrue(authorize("support", "read", "ticket"))

    def test_denies_unauthorized_and_unknown_roles(self):
        self.assertFalse(authorize("support", "delete", "ticket"))
        self.assertFalse(authorize("unknown", "read", "ticket"))


class MessageIntegrityTests(unittest.TestCase):
    def test_valid_message_verifies(self):
        key = b"test-key"
        envelope = sign_message({"action": "read", "resource": "ticket"}, key)
        self.assertTrue(verify_message(envelope, key))

    def test_tampering_and_wrong_key_are_rejected(self):
        envelope = sign_message({"action": "read"}, b"test-key")
        envelope["payload"]["action"] = "delete"
        self.assertFalse(verify_message(envelope, b"test-key"))
        self.assertFalse(verify_message(envelope, b"other-key"))

    def test_malformed_envelope_is_rejected(self):
        self.assertFalse(verify_message({"payload": [], "signature": "x"}, b"test-key"))


if __name__ == "__main__":
    unittest.main()
