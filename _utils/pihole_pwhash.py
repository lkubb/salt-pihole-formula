"""
This module is intended to verify PiHole password hashes against
provided passwords. It's used to manage the expected password.

Most of this code is taken and slightly modified from
https://github.com/nachonavarro/balloon-hashing/blob/8e28a7822113f1e8ef56b175550210c1a8e36c1a/balloon.py
which is licensed under the

MIT License

Copyright (c) 2017 Ignacio Navarro

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import base64
import hashlib
import re
import secrets

hash_functions = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha224": hashlib.sha224,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
}


def hash_func(*args, hash_type: str = "sha256") -> bytes:
    """Concatenate all the arguments and hash the result.
       Note that the hash function used can be modified
       in the global parameter `HASH_TYPE`.

    Args:
        *args: Arguments to concatenate.

    Returns:
        bytes: The hashed string.
    """
    t = b""

    for arg in args:
        if type(arg) is int:
            t += arg.to_bytes(8, "little")
        elif type(arg) is str:
            t += arg.encode("utf-8")
        else:
            t += arg

    return hash_functions[hash_type](t).digest()


def expand(
    buf: list[bytes], cnt: int, space_cost: int, /, hash_type: str = "sha256"
) -> int:
    """First step of the algorithm. Fill up a buffer with
       pseudorandom bytes derived from the password and salt
       by computing repeatedly the hash function on a combination
       of the password and the previous hash.

    Args:
        buf (list[bytes]): A list of hashes as bytes.
        cnt (int): Used in a security proof (read the paper).
        space_cost (int): The size of the buffer.

    Returns:
        int: Counter used in a security proof (read the paper).
    """
    for s in range(1, space_cost):
        buf.append(hash_func(cnt, buf[s - 1], hash_type=hash_type))
        cnt += 1
    return cnt


def mix(
    buf: list[bytes],
    cnt: int,
    delta: int,
    salt: bytes,
    space_cost: int,
    time_cost: int,
    /,
    hash_type: str = "sha256",
) -> None:
    """Second step of the algorithm. Mix `time_cost` number
       of times the pseudorandom bytes in the buffer. At each
       step in the for loop, update the nth block to be
       the hash of the n-1th block, the nth block, and `delta`
       other blocks chosen at random from the buffer `buf`.

    Args:
        buf (list[bytes]): A list of hashes as bytes.
        cnt (int): Used in a security proof (read the paper).
        delta (int): Number of random blocks to mix with.
        salt (bytes): A user defined random value for security.
        space_cost (int): The size of the buffer.
        time_cost (int): Number of rounds to mix.

    Returns:
        void: Updates the buffer and counter, but does not
        return anything.
    """
    for t in range(time_cost):
        for s in range(space_cost):
            buf[s] = hash_func(cnt, buf[s - 1], buf[s], hash_type=hash_type)
            cnt += 1
            for i in range(delta):
                idx_block = hash_func(t, s, i, hash_type=hash_type)
                other = (
                    int.from_bytes(
                        hash_func(cnt, salt, idx_block, hash_type=hash_type), "little"
                    )
                    % space_cost
                )
                cnt += 1
                buf[s] = hash_func(cnt, buf[s], buf[other], hash_type=hash_type)
                cnt += 1


def extract(buf: list[bytes]) -> bytes:
    """Final step. Return the last value in the buffer.

    Args:
        buf (list[bytes]): A list of hashes as bytes.

    Returns:
        bytes: Last value of the buffer as bytes.
    """
    return buf[-1]


def balloon(
    password: str,
    salt: str,
    space_cost: int,
    time_cost: int,
    delta: int = 3,
    hash_type: str = "sha256",
) -> bytes:
    """Main function that collects all the substeps. As
       previously mentioned, first expand, then mix, and
       finally extract. Note the result is returned as bytes,
       for a more friendly function with default values
       that returns a hex string, see the function `balloon_hash`.

    Args:
        password (str): The main string to hash.
        salt (str): A user defined random value for security.
        space_cost (int): The size of the buffer.
        time_cost (int): Number of rounds to mix.
        delta (int, optional): Number of random blocks to mix with. Defaults to 3.

    Returns:
        bytes: A series of bytes, the hash.
    """
    # Encode salt as bytes to be passed to _balloon()
    return _balloon(
        password,
        salt.encode("utf-8"),
        space_cost,
        time_cost,
        delta,
        hash_type=hash_type,
    )


def _balloon(
    password: str,
    salt: bytes,
    space_cost: int,
    time_cost: int,
    delta: int = 3,
    hash_type: str = "sha256",
) -> bytes:
    """For internal use. Implements steps outlined in `balloon`.

    Args:
        password (str): The main string to hash.
        salt (bytes): A user defined random value for security.
        space_cost (int): The size of the buffer.
        time_cost (int): Number of rounds to mix.
        delta (int, optional): Number of random blocks to mix with. Defaults to 3.

    Returns:
        bytes: A series of bytes, the hash.
    """
    if not isinstance(space_cost, int) or space_cost < 1:
        raise ValueError("'space_cost' must be a positive integer.")
    if not isinstance(time_cost, int) or time_cost < 1:
        raise ValueError("'time_cost' must be a positive integer.")
    if not isinstance(delta, int) or delta < 1:
        raise ValueError("'delta' must be a positive integer.")
    buf = [hash_func(0, password, salt, hash_type=hash_type)]
    cnt = 1

    cnt = expand(buf, cnt, space_cost)
    mix(buf, cnt, delta, salt, space_cost, time_cost)
    return extract(buf)


# The following code is original


def verify(serialized_hash: str, password: str, delta: int = 3):
    """
    Verify a PiHole serialized hash in the form of

        $BALLOON-SHA256$v=1$s=1024,t=32$dGhpcyBpcyB0aGUgc2FsdA==$aGkgdGhlcmUsIHllcywgdGhpcyBpcyBiYXNlNjQtZW5jb2RlZA==

    serialized_hash
        The hash as saved in ``pihole.toml``.

    password
        The password to check.

    delta
        Number of random blocks to mix with. Defaults to 3, which is
        hardcoded in gnutls. There should not be a need to modify this parameter.
    """
    parsed = _parse_hash(serialized_hash)
    return secrets.compare_digest(
        _balloon(
            password, parsed["salt"], parsed["space_cost"], parsed["time_cost"], delta
        ),
        parsed["hash"],
    )


def _parse_hash(hash_str):
    pattern = r"^\$(?P<algo>[^$]+)\$v=(?P<version>\d+)\$s=(?P<space_cost>\d+),t=(?P<time_cost>\d+)\$(?P<salt_base64>[^$]+)\$(?P<hash_base64>.+)$"
    parsed = re.match(pattern, hash_str)
    if not parsed:
        raise ValueError("Invalid PiHole balloon hash")
    groups = parsed.groupdict()
    if not groups["algo"].startswith("BALLOON-"):
        raise ValueError(f"Unsupported algorithm: {groups['algo']}")
    hash_type = groups["algo"][len("BALLOON-") :].lower()
    if hash_type not in hash_functions:
        raise ValueError(f"Unsupported hashing algorithm: {hash_type}")
    if groups["version"] != "1":
        raise ValueError(f"Unsupported algorithm version: {groups['version']}")
    salt_raw = base64.b64decode(groups["salt_base64"])
    hash_raw = base64.b64decode(groups["hash_base64"])
    return {
        "salt": salt_raw,
        "hash": hash_raw,
        "space_cost": int(groups["space_cost"]),
        "time_cost": int(groups["time_cost"]),
        "hash_type": hash_type,
    }
