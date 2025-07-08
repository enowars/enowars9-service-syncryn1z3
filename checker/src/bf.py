import math
import brainfuckery
import zlib
import re

from enochecker3 import (
    MumbleException,
)

# Copied from enochecker_test
def _encode_bf_normal(input: str) -> str:
    targets: list[int] = []
    sim_alloc_v: list[int] = []
    sim_alloc_p = 0
    codes = list(input.encode("utf-8"))

    for tc in codes:
        cost_new = (
            0 if tc == 0 else min(tc, math.ceil(math.sqrt(tc)) + 1 if tc > 0 else tc)
        )
        reusable_idx, reuse_cost = -1, tc
        for i, v_alloc in enumerate(sim_alloc_v):
            c = abs(v_alloc - tc) + abs(i - sim_alloc_p)
            if c < reuse_cost:
                reuse_cost, reusable_idx = c, i

        if reusable_idx == -1 or reuse_cost >= cost_new:
            sim_alloc_p = len(targets)
            targets.append(tc)
            sim_alloc_v.append(tc)
        else:
            sim_alloc_p = reusable_idx
            sim_alloc_v[sim_alloc_p] = tc

    bf = []
    l_factor = 1
    if targets:
        s_targets = sorted(targets)
        n = len(s_targets)
        med = (
            float(s_targets[n // 2])
            if n % 2 == 1
            else (s_targets[n // 2 - 1] + s_targets[n // 2]) / 2.0
        )
        if med > 0:
            l_factor = max(1, int(math.floor(math.sqrt(med) + 0.5)))

    inits = []
    setup_vals = []
    for t_val in targets:
        inc = int(math.floor((t_val / l_factor) + 0.5))
        inits.append(inc)
        setup_vals.append(inc * l_factor)

    if l_factor > 0:
        bf.append("+" * l_factor)
    bf.append("[")
    for inc_val in inits:
        bf.append(">")
        if inc_val > 0:
            bf.append("+" * inc_val)
    if inits:
        bf.append("<" * len(inits))
    bf.append("-")
    bf.append("]")
    if inits:
        bf.append(">")

    # Print Loop
    ptr = 0
    for tc in codes:
        best_p_idx, min_p_cost = 0, float("inf")
        for i, v_print in enumerate(setup_vals):
            c = abs(v_print - tc) + abs(i - ptr)
            if c < min_p_cost:
                min_p_cost, best_p_idx = c, i

        diff_ptr = ptr - best_p_idx
        if diff_ptr > 0:
            bf.append("<" * diff_ptr)
        elif diff_ptr < 0:
            bf.append(">" * -diff_ptr)

        val_in_cell = setup_vals[best_p_idx]
        diff_val = val_in_cell - tc
        if diff_val > 0:
            bf.append("-" * diff_val)
        elif diff_val < 0:
            bf.append("+" * -diff_val)

        bf.append(".")
        ptr = best_p_idx
        setup_vals[ptr] = tc

    return "".join(bf)

def _encode_bf_simple(input: str) -> str:
    bf = ""
    prev = 0

    for c in input:
        diff = ord(c) - prev
        prev = ord(c)

        if diff > 0:
            bf += "+" * diff + "."
        else:
            bf += "-" * (-diff) + "."

    return bf

def _decode_bf(input: str) -> str:
    return brainfuckery.Brainfuckery().interpret(input)

def is_bf(s: str):
    return re.fullmatch(r"@?[+\-<>\[\]\.]{100,}@?", s) is not None

def encode(input: str) -> bytes:
    decoded = _decode_bf(input)
    encoded = "@" + _encode_bf_simple(decoded) + "@"

    return zlib.compress(encoded.encode("ascii"), level=9)

def decode(input: bytes, reencode=False) -> str:
    try:
        decompressed = zlib.decompress(input).decode()
    except zlib.error:
        raise MumbleException("Failed to decompress flag")
    except UnicodeDecodeError:
        raise MumbleException("Failed to decode flag")

    if not reencode:
        return decompressed
    
    decoded = _decode_bf(decompressed)
    
    return "@" + _encode_bf_normal(decoded) + "@"
