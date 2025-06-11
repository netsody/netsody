#
# Copyright (c) 2020-2025 Heiko Bornholdt and Kevin Röbert
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
# DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
# OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
# OR OTHER DEALINGS IN THE SOFTWARE.
#
from ctypes import *
import os
import platform
import json

from functools import wraps
import inspect

_dir = os.path.dirname(os.path.realpath(__file__))
# get the right filename
if platform.uname()[0] == "Windows":
    _name = "drasyl.dll"
elif platform.uname()[0] == "Linux":
    _name = "libdrasyl.so"
else:
    _name = "libdrasyl.dylib"
_libdrasyl = cdll.LoadLibrary(os.path.join(_dir, "libdrasyl", _name))

#
# utils
#

class Identity:
    def __init__(self, secret_key: bytes, public_key: bytes, proof_of_work: int):
        self.secret_key = secret_key
        self.public_key = public_key
        self.proof_of_work = proof_of_work

    def __str__(self):
        return (
            "{\n"
            f"  secret_key: {self.secret_key.hex()},\n"
            f"  public_key: {self.public_key.hex()},\n"
            f"  proof_of_work: {self.proof_of_work}\n"
            "}"
        )

    def to_dict(self):
        return {
            "secret_key": self.secret_key.hex(),
            "public_key": self.public_key.hex(),
            "proof_of_work": self.proof_of_work,
        }

    @classmethod
    def from_dict(cls, d):
        return cls(
            secret_key=bytes.fromhex(d["secret_key"]),
            public_key=bytes.fromhex(d["public_key"]),
            proof_of_work=d["proof_of_work"],
        )

    def save_to_file(self, filename):
        with open(filename, "w") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load_from_file(cls, filename):
        with open(filename) as f:
            data = json.load(f)
        return cls.from_dict(data)

def check_not_none(*allowed_none_args):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            sig = inspect.signature(func)
            bound_args = sig.bind(*args, **kwargs)
            bound_args.apply_defaults()

            for name, value in bound_args.arguments.items():
                if name not in allowed_none_args and value is None:
                    raise ValueError(f"Argument '{name}' must not be None.")

            return func(*args, **kwargs)
        return wrapper
    return decorator

def success(code: int):
    return code == 0

#
# Return codes
#

# Signals a null pointer exception
ERR_NULL_POINTER = -6
# Signals an identity generation error
ERR_IDENTITY_GENERATION = -7

# === Constants matching Rust definitions ===
ED25519_SECRETKEYBYTES = 64
ED25519_PUBLICKEYBYTES = 32
POW_BYTES = 4
DEFAULT_POW_DIFFICULTY = 24

#
# Libdrasyl functions
#
def drasyl_version():
    # Set argument and return types for the Rust FFI function
    _libdrasyl.drasyl_version.restype = c_char_p

    version = _libdrasyl.drasyl_version()
    return version.decode("utf-8").strip("\0")

def drasyl_generate_identity(pow_difficulty = DEFAULT_POW_DIFFICULTY):
    """
Calls the Rust `generate_identity` function and returns
the generated secret key, public key, and proof of work as bytes.

Returns:
tuple(bytes, bytes, bytes): (secret_key, public_key, proof_of_work)

Raises:
RuntimeError: If the Rust function returns an error code.
    """

    # Set argument and return types for the Rust FFI function
    _libdrasyl.drasyl_generate_identity.argtypes = [
        POINTER(c_ubyte),  # secret key buffer
        POINTER(c_ubyte),  # public key buffer
        POINTER(c_ubyte),  # proof of work buffer
        c_uint8
    ]
    _libdrasyl.drasyl_generate_identity.restype = c_int

    # Allocate buffers for the output data
    sk = (c_ubyte * ED25519_SECRETKEYBYTES)()
    pk = (c_ubyte * ED25519_PUBLICKEYBYTES)()
    pow_buf = (c_ubyte * POW_BYTES)()

    # Call the Rust function
    result = _libdrasyl.drasyl_generate_identity(sk, pk, pow_buf, pow_difficulty)

    # Handle possible error codes from Rust
    if result == 0:
        return Identity(bytes(sk), bytes(pk), int.from_bytes(pow_buf, byteorder='big', signed=True))
    elif result == ERR_NULL_POINTER:
        raise RuntimeError("Null pointer passed to generate_identity()")
    elif result == ERR_IDENTITY_GENERATION:
        raise RuntimeError("Identity generation failed")
    elif result != 0:
        raise RuntimeError(f"Unknown error code returned: {result}")

    return None


# MessageSink

# Returns the length of the recv buffer for the given bindAddr and message receiver
@check_not_none()
def drasyl_recv_buf_len(bind_addr: c_void_p, recv_buf_rx: c_void_p):
    # Set argument and return types for the Rust FFI function
    _libdrasyl.drasyl_recv_buf_len.argtypes = [
        c_void_p,  # bindAddr
        c_void_p   # recv_buf_rx
    ]
    _libdrasyl.drasyl_recv_buf_len.restype = c_int

    return _libdrasyl.drasyl_recv_buf_len(bind_addr, recv_buf_rx)

# NodeOptsBuilder

# Returns a pointer to a newly created node opts builder object
def drasyl_node_opts_builder_new():
    # Set argument and return types for the Rust FFI function
    _libdrasyl.drasyl_node_opts_builder_new.restype = c_void_p

    return _libdrasyl.drasyl_node_opts_builder_new()

@check_not_none()
def drasyl_node_opts_builder_id(bind_addr: c_void_p, identity: Identity):
    # Set argument and return types for the Rust FFI function
    _libdrasyl.drasyl_node_opts_builder_id.argtypes = [
        c_void_p,  # bindAddr
        c_void_p   # recv_buf_rx
    ]
    _libdrasyl.drasyl_node_opts_builder_id.restype = c_int

    result = _libdrasyl.drasyl_node_opts_builder_id(bind_addr, identity.secret_key, identity.proof_of_work)

    if not success(result):
        raise RuntimeError("Unexpected error")