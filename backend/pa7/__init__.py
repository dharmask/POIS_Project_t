"""PA#7 - Merkle-Damgard transform."""

from .merkle_damgard import (
    MerkleDamgard,
    md_strengthen,
    toy_compress,
    toy_collision_pair,
    toy_collision_propagation_demo,
    hash_message,
)

__all__ = [
    "MerkleDamgard",
    "md_strengthen",
    "toy_compress",
    "toy_collision_pair",
    "toy_collision_propagation_demo",
    "hash_message",
]
