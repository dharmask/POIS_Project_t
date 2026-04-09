"""
Tests for PA#8 - DLP-based collision-resistant hash.
"""

from backend.pa8.dlp_hash import (
    DLPHash,
    FULL_PARAMS,
    TOY_PARAMS,
    birthday_collision_demo,
    compress_bytes,
    compress_pair,
    compression_collision_reduction_demo,
    hash_bytes,
    hash_hex,
    hash_truncated,
)


class TestDLPCompression:
    def test_compression_is_deterministic(self):
        out1 = compress_pair(123, 456, TOY_PARAMS)
        out2 = compress_pair(123, 456, TOY_PARAMS)
        assert out1 == out2

    def test_compression_byte_wrapper_is_deterministic(self):
        chaining = bytes.fromhex("0011")
        block = bytes.fromhex("aa55")
        assert compress_bytes(chaining, block, TOY_PARAMS) == compress_bytes(chaining, block, TOY_PARAMS)


class TestDLPHash:
    def setup_method(self):
        self.hasher = DLPHash(FULL_PARAMS)

    def test_same_message_same_digest(self):
        message = b"same message"
        assert self.hasher.hash_bytes(message) == self.hasher.hash_bytes(message)

    def test_five_distinct_messages_produce_distinct_digests(self):
        messages = [
            b"",
            b"a",
            b"ab",
            b"abc",
            b"message that spans multiple full PA8 blocks",
        ]
        digests = [self.hasher.hash_hex(message) for message in messages]
        assert len(set(digests)) == len(messages)

    def test_empty_input_works(self):
        digest = self.hasher.hash_bytes(b"")
        assert isinstance(digest, bytes)
        assert len(digest) == FULL_PARAMS.group_bytes

    def test_one_block_input_works(self):
        digest = self.hasher.hash_bytes(b"A")
        assert len(digest) == FULL_PARAMS.group_bytes

    def test_multi_block_input_works(self):
        digest = self.hasher.hash_bytes(b"PA8 multi-block " * 20)
        assert len(digest) == FULL_PARAMS.group_bytes

    def test_truncation_returns_requested_length(self):
        digest = hash_truncated(b"truncate me", 16, FULL_PARAMS)
        assert len(digest) == 2
        assert digest == hash_bytes(b"truncate me", 16, FULL_PARAMS)

    def test_hash_hex_output_format_is_stable(self):
        digest = hash_hex(b"stable output", params=FULL_PARAMS)
        assert digest == hash_hex(b"stable output", params=FULL_PARAMS)
        assert len(digest) == FULL_PARAMS.group_bytes * 2
        assert digest == digest.lower()

    def test_trace_reports_truncated_and_full_digest(self):
        trace = self.hasher.trace(b"trace me", output_bits=12)
        assert trace["full_digest_hex"] != ""
        assert trace["digest_hex"] != ""
        assert trace["output_bits"] == 12
        assert len(trace["steps"]) >= 1


class TestCollisionDemos:
    def test_compression_collision_demo_recovers_toy_alpha(self):
        demo = compression_collision_reduction_demo(TOY_PARAMS)
        assert demo["collision_found"] is True
        assert demo["recovery_matches"] is True
        assert demo["recovered_alpha"] == TOY_PARAMS.demo_alpha

    def test_birthday_collision_demo_finds_collision(self):
        demo = birthday_collision_demo(
            bits=8,
            params=TOY_PARAMS,
            max_attempts=400,
            message_factory=lambda i: i.to_bytes(2, "big"),
        )
        assert demo["message1_hex"] != demo["message2_hex"]
        assert demo["truncated_digest_hex"] != ""
        assert demo["compression_reduction_demo"]["recovery_matches"] is True
