"""
PA#7 - Merkle-Damgard transform.

Generic domain extension for a fixed-length compression function h:
  h : {0,1}^{n+b} -> {0,1}^n

This module keeps the interface generic so PA#8 can plug in its own
compression function directly, while PA#7 itself ships with a toy XOR-based
compression function for isolated testing and visual demos.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


CompressionFn = Callable[[bytes, bytes], bytes]


def md_strengthen(message: bytes, block_size: int, length_field_bytes: int = 8) -> bytes:
    """
    MD-strengthening padding:
      M || 1 || 0* || <|M|>

    The final length field stores the original message length in bits, encoded
    as a big-endian unsigned integer.
    """
    if block_size <= 0:
        raise ValueError("block_size must be positive")
    if length_field_bytes <= 0:
        raise ValueError("length_field_bytes must be positive")
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("message must be bytes")

    msg = bytes(message)
    bit_length = len(msg) * 8
    padded = msg + b"\x80"
    while (len(padded) + length_field_bytes) % block_size != 0:
        padded += b"\x00"
    padded += bit_length.to_bytes(length_field_bytes, "big")
    return padded


@dataclass(slots=True)
class MerkleDamgard:
    compress: CompressionFn
    iv: bytes
    block_size: int
    output_size: int | None = None
    length_field_bytes: int = 8

    def __post_init__(self) -> None:
        if not callable(self.compress):
            raise TypeError("compress must be callable")
        if not isinstance(self.iv, (bytes, bytearray)):
            raise TypeError("iv must be bytes")
        self.iv = bytes(self.iv)
        if not self.iv:
            raise ValueError("iv must be non-empty")
        if self.block_size <= 0:
            raise ValueError("block_size must be positive")
        if self.length_field_bytes <= 0:
            raise ValueError("length_field_bytes must be positive")
        if self.output_size is None:
            self.output_size = len(self.iv)
        if self.output_size != len(self.iv):
            raise ValueError("output_size must match len(iv)")

    def pad(self, message: bytes) -> bytes:
        return md_strengthen(message, self.block_size, self.length_field_bytes)

    def iter_blocks(self, message: bytes) -> list[bytes]:
        padded = self.pad(message)
        return [padded[i:i + self.block_size] for i in range(0, len(padded), self.block_size)]

    def hash(self, message: bytes) -> bytes:
        state = self.iv
        for block in self.iter_blocks(message):
            state = self.compress(state, block)
            if len(state) != self.output_size:
                raise ValueError("compression function returned wrong output length")
        return state

    def trace_blocks(self, blocks: list[bytes]) -> dict:
        if not isinstance(blocks, list) or not blocks:
            raise ValueError("blocks must be a non-empty list")
        state = self.iv
        steps = []
        chaining_values = [state.hex()]
        blocks_hex = []
        for idx, block in enumerate(blocks, start=1):
            if not isinstance(block, (bytes, bytearray)):
                raise TypeError("each block must be bytes")
            block_bytes = bytes(block)
            if len(block_bytes) != self.block_size:
                raise ValueError("every block must match the configured block size")
            next_state = self.compress(state, block_bytes)
            if len(next_state) != self.output_size:
                raise ValueError("compression function returned wrong output length")
            blocks_hex.append(block_bytes.hex())
            steps.append(
                {
                    "index": idx,
                    "block_hex": block_bytes.hex(),
                    "chaining_in_hex": state.hex(),
                    "chaining_out_hex": next_state.hex(),
                }
            )
            state = next_state
            chaining_values.append(state.hex())
        return {
            "block_size": self.block_size,
            "output_size": self.output_size,
            "iv_hex": self.iv.hex(),
            "blocks_hex": blocks_hex,
            "chaining_values_hex": chaining_values,
            "steps": steps,
            "digest_hex": state.hex(),
        }

    def trace(self, message: bytes) -> dict:
        msg = bytes(message)
        padded = self.pad(msg)
        blocks = [padded[i:i + self.block_size] for i in range(0, len(padded), self.block_size)]
        result = self.trace_blocks(blocks)
        return {
            "message_hex": msg.hex(),
            "message_length_bytes": len(msg),
            "message_length_bits": len(msg) * 8,
            "padded_hex": padded.hex(),
            **result,
        }


def toy_compress(chaining_value: bytes, block: bytes) -> bytes:
    """
    Toy compression function for PA#7.

    For the default PA#7 demo parameters:
      n = 4 bytes, b = 8 bytes
      h(z, m0||m1) = z xor m0 xor m1
    """
    if len(chaining_value) == 0:
        raise ValueError("chaining_value must be non-empty")
    n = len(chaining_value)
    if len(block) == 0 or len(block) % n != 0:
        raise ValueError("block length must be a positive multiple of the chaining length")

    state = bytes(chaining_value)
    for offset in range(0, len(block), n):
        chunk = block[offset:offset + n]
        state = bytes(a ^ b for a, b in zip(state, chunk))
    return state


def hash_message(
    message: bytes,
    compress: CompressionFn = toy_compress,
    *,
    iv: bytes | None = None,
    block_size: int = 8,
    output_size: int = 4,
) -> bytes:
    iv_bytes = bytes(output_size) if iv is None else bytes(iv)
    md = MerkleDamgard(compress=compress, iv=iv_bytes, block_size=block_size, output_size=output_size)
    return md.hash(message)


def toy_collision_pair() -> tuple[bytes, bytes]:
    """
    Two distinct 8-byte blocks that collide under toy_compress for the same IV.

    block1 = A || B
    block2 = (A xor D) || (B xor D)
    Since toy_compress xors both halves, both blocks produce the same output.
    """
    left = bytes.fromhex("10203040")
    right = bytes.fromhex("55667788")
    delta = bytes.fromhex("deadbeef")
    block1 = left + right
    block2 = bytes(a ^ b for a, b in zip(left, delta)) + bytes(a ^ b for a, b in zip(right, delta))
    return block1, block2


def toy_collision_propagation_demo() -> dict:
    """
    Demonstrate that a collision in the toy compression function propagates to
    a collision in the full MD hash when the colliding messages have equal
    length and therefore identical padding blocks.
    """
    iv = bytes(4)
    md = MerkleDamgard(compress=toy_compress, iv=iv, block_size=8, output_size=4)
    m1, m2 = toy_collision_pair()

    compression_out_1 = toy_compress(iv, m1)
    compression_out_2 = toy_compress(iv, m2)
    trace_1 = md.trace(m1)
    trace_2 = md.trace(m2)

    return {
        "compression_collision": compression_out_1 == compression_out_2,
        "messages_distinct": m1 != m2,
        "message1_hex": m1.hex(),
        "message2_hex": m2.hex(),
        "compression_output_hex": compression_out_1.hex(),
        "hash1_hex": trace_1["digest_hex"],
        "hash2_hex": trace_2["digest_hex"],
        "hash_collision": trace_1["digest_hex"] == trace_2["digest_hex"],
        "trace1": trace_1,
        "trace2": trace_2,
        "explanation": (
            "Both 8-byte messages collide in the first compression step. "
            "Because they have the same length, MD-strengthening appends the same padding block, "
            "so the remaining chain is identical and the final hashes collide too."
        ),
    }
