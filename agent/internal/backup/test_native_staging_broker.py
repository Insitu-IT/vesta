"""Peer and request boundaries for the allocation-only staging broker."""

import json
import socket
import struct
import unittest
from pathlib import Path
from unittest.mock import patch

import native_staging_broker as broker
import native_write_fence as fence
from test_libvirt_push import request


class Stream:
    def __init__(self, body, uid=1000):
        self.body = bytearray(body)
        self.uid = uid
        self.output = b""

    def settimeout(self, value):
        pass

    def getsockopt(self, level, option, size):
        assert level == socket.SOL_SOCKET and option == socket.SO_PEERCRED
        return struct.pack("3i", 123, self.uid, 1000)

    def recv(self, count):
        value = bytes(self.body[: min(count, 3)])
        del self.body[: len(value)]
        return value

    def sendall(self, body):
        self.output += body


class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.broker = broker.Broker("/protected", 1000, 1000, 10, 20, 1)
        self.request = request(Path("/protected/33333333-3333-4333-8333-333333333333"))

    def stream(self, value, uid=1000):
        body = json.dumps(value).encode()
        return Stream(struct.pack("!I", len(body)) + body, uid)

    def test_exact_request_only_allocates_bound_slot(self):
        stream = self.stream({"action": "allocate", "request": self.request})
        sha = broker.hashlib.sha256(broker.push.canonical(self.request)).hexdigest()
        with patch.object(
            fence, "allocate_attempt", return_value={"request_sha256": sha}
        ) as allocate:
            self.broker.handle(stream)
            self.assertEqual(allocate.call_count, 1)
            self.assertEqual(
                allocate.call_args.args, (Path("/protected"), self.request)
            )
        n = struct.unpack("!I", stream.output[:4])[0]
        self.assertEqual(len(stream.output[4:]), n)
        self.assertEqual(json.loads(stream.output[4:])["request_sha256"], sha)

    def test_invalid_peer_and_budget_configuration_refused(self):
        for uid, reserved, capacity in [
            (0, 1, 2),
            (True, 1, 2),
            (1000, 0, 2),
            (1000, 3, 2),
        ]:
            with (
                self.subTest(uid=uid, reserved=reserved, capacity=capacity),
                self.assertRaises(fence.FenceRefused),
            ):
                broker.Broker("/protected", uid, 1000, reserved, capacity, 1)

    def test_wrong_peer_never_parses_or_allocates(self):
        stream = self.stream({"action": "allocate", "request": self.request}, uid=1001)
        with patch.object(fence, "allocate_attempt") as allocate:
            with self.assertRaises(fence.FenceRefused):
                self.broker.handle(stream)
            allocate.assert_not_called()
        self.assertFalse(stream.output)

    def test_arbitrary_actions_paths_and_unknown_fields_refused(self):
        wrong = dict(
            self.request, output_path="/foreign/33333333-3333-4333-8333-333333333333"
        )
        values = [
            {"action": "fence", "request": self.request},
            {"action": "allocate", "request": wrong},
            {"action": "allocate", "request": self.request, "command": "anything"},
        ]
        with patch.object(fence, "allocate_attempt") as allocate:
            for value in values:
                with (
                    self.subTest(value=value),
                    self.assertRaises((fence.FenceRefused, broker.push.Uncertain)),
                ):
                    self.broker.handle(self.stream(value))
            allocate.assert_not_called()

    def test_duplicate_oversized_and_truncated_frames_refused(self):
        duplicate = b'{"action":"allocate","action":"allocate","request":{}}'
        frames = [
            struct.pack("!I", len(duplicate)) + duplicate,
            struct.pack("!I", broker.push.MAX_JSON + 1),
            struct.pack("!I", 10) + b"{}",
            struct.pack("!I", 0),
        ]
        with patch.object(fence, "allocate_attempt") as allocate:
            for frame in frames:
                with (
                    self.subTest(frame=frame),
                    self.assertRaises((fence.FenceRefused, ValueError)),
                ):
                    self.broker.handle(Stream(frame))
            allocate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
