"""
Tests for PA#7 - Merkle-Damgard transform.
"""

import pytest

from backend.pa7.merkle_damgard import (
    MerkleDamgard,
    hash_message,
    md_strengthen,
    toy_collision_pair,
    toy_collision_propagation_demo,
    toy_compress,
)


class TestPadding:
    def test_padding_empty_message(self):
        padded = md_strengthen(b"", block_size=8)
        assert len(padded) == 16
        assert padded == bytes.fromhex("80000000000000000000000000000000")

    def test_padding_encodes_bit_length(self):
        padded = md_strengthen(b"abc", block_size=16)
        assert len(padded) % 16 == 0
        assert padded[-8:] == (24).to_bytes(8, "big")

    def test_padding_boundary_case_exact_block(self):
        padded = md_strengthen(b"A" * 8, block_size=16)
        assert len(padded) == 32
        assert padded[-8:] == (64).to_bytes(8, "big")

    def test_invalid_zero_block_size_rejected(self):
        with pytest.raises(ValueError):
            md_strengthen(b"abc", block_size=0, length_field_bytes=8)


class TestToyCompression:
    def test_toy_compress_default_formula(self):
        cv = bytes.fromhex("01020304")
        block = bytes.fromhex("1020304055667788")
        assert toy_compress(cv, block) == bytes.fromhex("444444cc")

    def test_toy_collision_pair_collides(self):
        m1, m2 = toy_collision_pair()
        assert m1 != m2
        assert toy_compress(bytes(4), m1) == toy_compress(bytes(4), m2)


class TestMerkleDamgard:
    def setup_method(self):
        self.md = MerkleDamgard(compress=toy_compress, iv=bytes(4), block_size=8, output_size=4)

    def test_empty_message_hashes_to_expected_digest(self):
        assert self.md.hash(b"") == bytes.fromhex("80000000")

    def test_one_block_message_hash_length(self):
        digest = self.md.hash(b"abcd")
        assert isinstance(digest, bytes)
        assert len(digest) == 4

    def test_multi_block_message_hash_length(self):
        digest = self.md.hash(b"this message spans more than one toy block")
        assert len(digest) == 4

    def test_trace_exposes_all_chain_steps(self):
        trace = self.md.trace(b"abcdefgh")
        assert trace["iv_hex"] == "00000000"
        assert len(trace["blocks_hex"]) == 3
        assert len(trace["steps"]) == 3
        assert len(trace["chaining_values_hex"]) == 4
        assert trace["digest_hex"] == trace["chaining_values_hex"][-1]

    def test_hash_message_helper_matches_class(self):
        message = b"helper test"
        assert hash_message(message) == self.md.hash(message)

    def test_trace_blocks_replays_explicit_blocks(self):
        blocks = [bytes.fromhex("6162636465666768"), bytes.fromhex("8000000000000000")]
        trace = self.md.trace_blocks(blocks)
        assert trace["blocks_hex"] == [block.hex() for block in blocks]
        assert len(trace["steps"]) == 2
        assert trace["chaining_values_hex"][0] == "00000000"

    def test_bad_compression_output_length_rejected(self):
        def bad_compress(cv: bytes, block: bytes) -> bytes:
            return b"\x00"

        md = MerkleDamgard(compress=bad_compress, iv=bytes(4), block_size=8, output_size=4)
        with pytest.raises(ValueError):
            md.hash(b"abc")


class TestCollisionPropagation:
    def test_collision_propagation_demo(self):
        result = toy_collision_propagation_demo()
        assert result["messages_distinct"] is True
        assert result["compression_collision"] is True
        assert result["hash_collision"] is True
        assert result["hash1_hex"] == result["hash2_hex"]
