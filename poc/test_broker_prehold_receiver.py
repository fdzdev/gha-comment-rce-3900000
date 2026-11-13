#!/usr/bin/env python3

import contextlib
import importlib.util
import io
import json
import pathlib
import unittest


PATH = pathlib.Path(__file__).with_name("broker_prehold_receiver.py")
SPEC = importlib.util.spec_from_file_location("broker_prehold_receiver", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class FakeRequests:
    def __init__(self, billing_owner="B", run_url="https://run-actions.actions.githubusercontent.com/168/"):
        self.billing_owner = billing_owner
        self.run_url = run_url
        self.acquire_calls = 0

    def __call__(self, method, url, token, body=None, timeout=8):
        if method == "GET" and "/message?" in url:
            reference = {
                "runner_request_id": "controlled-request",
                "billing_owner_id": self.billing_owner,
                "run_service_url": self.run_url,
            }
            return 200, json.dumps({
                "messageId": 1,
                "messageType": "RunnerJobRequest",
                "body": json.dumps(reference),
            }).encode()
        if method == "POST" and url.endswith("/acquirejob"):
            self.acquire_calls += 1
            github = {"t": 2, "d": [
                {"k": "repository", "v": "owner/receiver"},
                {"k": "run_id", "v": "4242"},
            ]}
            return 200, json.dumps({
                "messageType": "PipelineAgentJobRequest",
                "contextData": {"github": github},
                "environmentVariables": [{"BROKER_RECEIVER_NONCE": "B-NONCE-4242"}],
            }).encode()
        raise AssertionError((method, url))


class ReceiverTests(unittest.TestCase):
    def test_future_window_offset(self):
        self.assertEqual(MODULE.future_target(1000, "next", 8), 1008)
        self.assertEqual(MODULE.future_target(1000, "999", 8), 999)
        with self.assertRaisesRegex(MODULE.ReceiverError, "invalid_target_offset"):
            MODULE.future_target(1000, "next", 33)

    def test_prehold_uses_one_future_agent_and_returns_only_in_memory(self):
        posts = []

        def request(method, url, token, body=None, timeout=8):
            if method == "DELETE":
                return 204, b""
            posts.append(body)
            if len(posts) == 1:
                return 409, b'junk that must not be emitted'
            return 201, b'{"sessionId":"00000000-0000-0000-0000-000000000009"}'

        candidates = [
            b"00000000-0000-0000-0000-000000000001",
            b"00000000-0000-0000-0000-000000000002",
        ]
        held, queued = MODULE.prehold(
            "secret", "https://broker.actions.githubusercontent.com", "2.338.2",
            1000000500, candidates, request_fn=request,
        )
        self.assertEqual(held, "00000000-0000-0000-0000-000000000009")
        self.assertFalse(queued)
        self.assertEqual(posts[-1]["agent"]["id"], 1000000500)
        self.assertEqual(posts[-1]["agent"]["name"], "GitHub Actions 1000000500")

    def test_accepts_only_expected_receiver_and_emits_safe_line(self):
        calls = FakeRequests()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            MODULE.receiver(
                "secret", "https://broker.actions.githubusercontent.com", "2.338.2",
                "00000000-0000-0000-0000-000000000001", "B", "owner/receiver",
                "4242", "B-NONCE-4242", 1, request_fn=calls,
            )
        self.assertEqual(calls.acquire_calls, 1)
        self.assertEqual(
            output.getvalue().strip(),
            "BROKER_RECEIVER message_type=RunnerJobRequest repo=owner/receiver "
            "run=4242 nonce=B-NONCE-4242",
        )
        self.assertNotIn("secret", output.getvalue())
        self.assertNotIn("controlled-request", output.getvalue())

    def test_owner_mismatch_skips_acquisition(self):
        calls = FakeRequests(billing_owner="not-owned")
        with self.assertRaisesRegex(MODULE.ReceiverError, "receiver_owner_mismatch"):
            MODULE.receiver(
                "secret", "https://broker.actions.githubusercontent.com", "2.338.2",
                "00000000-0000-0000-0000-000000000001", "B", "owner/receiver",
                "4242", "B-NONCE-4242", 1, request_fn=calls,
            )
        self.assertEqual(calls.acquire_calls, 0)

    def test_invalid_run_service_url_skips_acquisition(self):
        calls = FakeRequests(run_url="https://attacker.invalid/168/")
        with self.assertRaisesRegex(MODULE.ReceiverError, "invalid_run_service_reference"):
            MODULE.receiver(
                "secret", "https://broker.actions.githubusercontent.com", "2.338.2",
                "00000000-0000-0000-0000-000000000001", "B", "owner/receiver",
                "4242", "B-NONCE-4242", 1, request_fn=calls,
            )
        self.assertEqual(calls.acquire_calls, 0)

    def test_context_decoder_matches_runner_wire_shape(self):
        value = {"t": 2, "d": [{"k": "run_id", "v": "4242"}]}
        self.assertEqual(MODULE.decode_context(value), {"run_id": "4242"})


if __name__ == "__main__":
    unittest.main()
