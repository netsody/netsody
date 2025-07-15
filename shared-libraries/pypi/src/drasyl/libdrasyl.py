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
import ctypes
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

def validate_ctypes(strict_convert=False):
    """
Decorator that validates:
- Compatibility with annotated ctypes types
- Value ranges for ctypes integer types
- Optionally auto-converts compatible raw values to ctypes instances
    """
    def decorator(func):
        sig = inspect.signature(func)

        @wraps(func)
        def wrapper(*args, **kwargs):
            bound_args = sig.bind(*args, **kwargs)
            bound_args.apply_defaults()

            for name, value in bound_args.arguments.items():
                # Type annotation of the argument
                expected_type = sig.parameters[name].annotation

                # Skip if no type annotation or not a ctypes type
                if expected_type is inspect._empty or not issubclass_safe(expected_type, ctypes._SimpleCData):
                    continue

                # If already the correct ctypes type, allow it
                if isinstance(value, expected_type):
                    continue

                # Try conversion or validation
                try:
                    # Integer range validation for numeric types
                    raw_value = int(value)
                    min_val, max_val = get_ctypes_range(expected_type)
                    if not (min_val <= raw_value <= max_val):
                        raise ValueError(f"Argument '{name}'={raw_value} is out of range for {expected_type.__name__} ({min_val}–{max_val})")

                    # Auto-convert if strict mode is on
                    if strict_convert:
                        bound_args.arguments[name] = expected_type(raw_value)

                except Exception as e:
                    raise TypeError(f"Argument '{name}' cannot be used as {expected_type.__name__}: {e}")

            return func(*bound_args.args, **bound_args.kwargs)

        return wrapper
    return decorator


def get_ctypes_range(ctype):
    """
Return min and max allowed values for a given ctypes integer type.
    """
    if issubclass(ctype, ctypes._SimpleCData):
        size = ctypes.sizeof(ctype)
        signed = hasattr(ctype, 'value') and ctype(-1).value < 0
        if signed:
            min_val = -(2 ** (size * 8 - 1))
            max_val = 2 ** (size * 8 - 1) - 1
        else:
            min_val = 0
            max_val = 2 ** (size * 8) - 1
        return min_val, max_val
    raise TypeError("Unsupported ctypes type for range check")


def issubclass_safe(obj, cls):
    """
Safe check to determine if obj is a subclass of cls.
    """
    try:
        return issubclass(obj, cls)
    except TypeError:
        return False

def success(code: int):
    return code == 0

def ensure_success(code: int):
    if code != 0:
        raise RuntimeError("Unexpected error code " + str(code))

#
# Return codes
#

# Signals an UTF-8 encoding error
ERR_UTF8 = -1
# Signals an error during address parsing
ERR_ADDR_PARSE = -4
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
@validate_ctypes()
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

# Adds an identity to the node opts builder
@validate_ctypes()
@check_not_none()
def drasyl_node_opts_builder_id(builder: c_void_p, identity: Identity):
    # Set argument and return types for the Rust FFI function
    _libdrasyl.drasyl_node_opts_builder_id.argtypes = [
        c_void_p,  # builder
        c_void_p   # recv_buf_rx
    ]
    _libdrasyl.drasyl_node_opts_builder_id.restype = c_int

    ensure_success(_libdrasyl.drasyl_node_opts_builder_id(builder, identity.secret_key, identity.proof_of_work))

@validate_ctypes()
@check_not_none()
def drasyl_node_opts_builder_message_sink(builder: c_void_p, recv_buf_tx: c_void_p):
    # Set argument and return types for the Rust FFI function
    _libdrasyl.drasyl_node_opts_builder_message_sink.argtypes = [
        c_void_p,  # builder
        c_void_p   # recv_buf_tx
    ]
    _libdrasyl.drasyl_node_opts_builder_message_sink.restype = c_int

    ensure_success(_libdrasyl.drasyl_node_opts_builder_message_sink(builder, recv_buf_tx))

@validate_ctypes()
@check_not_none()
def drasyl_node_opts_builder_network_id(builder: c_void_p, network_id: c_int32):
    # Set argument and return types for the Rust FFI function
    _libdrasyl.drasyl_node_opts_builder_network_id.argtypes = [
        c_void_p,  # builder
        c_void_p   # network_id
    ]
    _libdrasyl.drasyl_node_opts_builder_network_id.restype = c_int

    ensure_success(_libdrasyl.drasyl_node_opts_builder_network_id(builder, network_id))

@validate_ctypes()
@check_not_none()
def drasyl_node_opts_builder_udp_addrs(builder: c_void_p, udp_addrs: str):
    # Set argument and return types for the Rust FFI function
    _libdrasyl.drasyl_node_opts_builder_udp_addrs.argtypes = [
        c_void_p,  # builder
        c_char_p   # udp_addrs
    ]
    _libdrasyl.drasyl_node_opts_builder_udp_addrs.restype = c_int

    result = _libdrasyl.drasyl_node_opts_builder_udp_addrs(builder, udp_addrs.encode('utf-8'))

    if result == ERR_UTF8:
        raise RuntimeError("Address is not in valid utf-8 format.")
    elif result == ERR_ADDR_PARSE:
        raise RuntimeError("Address is not in a valid format.")

    ensure_success(result)

@validate_ctypes()
@check_not_none()
def drasyl_node_opts_builder_udp_port(builder: c_void_p, udp_port: c_ushort):
    # Set argument and return types for the Rust FFI function
    _libdrasyl.drasyl_node_opts_builder_udp_port.argtypes = [
        c_void_p,  # builder
        c_ushort   # udp_port
    ]
    _libdrasyl.drasyl_node_opts_builder_udp_port.restype = c_int

    ensure_success(_libdrasyl.drasyl_node_opts_builder_udp_port(builder, udp_port))

@check_not_none()
def drasyl_node_opts_builder_udp_port_none(builder: c_void_p):
    # Set argument and return types for the Rust FFI function
    _libdrasyl.drasyl_node_opts_builder_udp_port_none.argtypes = [
        c_void_p  # builder
    ]
    _libdrasyl.drasyl_node_opts_builder_udp_port_none.restype = c_int

    ensure_success(_libdrasyl.drasyl_node_opts_builder_udp_port_none(builder))

@validate_ctypes()
@check_not_none()
def drasyl_node_opts_builder_arm_messages(builder: c_void_p, arm_messages: c_bool):
    # Set argument and return types for the Rust FFI function
    _libdrasyl.drasyl_node_opts_builder_arm_messages.argtypes = [
        c_void_p,  # builder
        c_bool     # arm_messages
    ]
    _libdrasyl.drasyl_node_opts_builder_arm_messages.restype = c_int

    ensure_success(_libdrasyl.drasyl_node_opts_builder_arm_messages(builder, arm_messages))

@validate_ctypes()
@check_not_none()
def drasyl_node_opts_builder_max_peers(builder: c_void_p, max_peers: c_uint64):
    # Set argument and return types for the Rust FFI function
    _libdrasyl.drasyl_node_opts_builder_max_peers.argtypes = [
        c_void_p,  # builder
        c_uint64   # max_peers
    ]
    _libdrasyl.drasyl_node_opts_builder_max_peers.restype = c_int

    ensure_success(_libdrasyl.drasyl_node_opts_builder_max_peers(builder, max_peers))

@validate_ctypes()
@check_not_none()
def drasyl_node_opts_builder_min_pow_difficulty(builder: c_void_p, min_pow_difficulty: c_uint8):
    # Set argument and return types for the Rust FFI function
    _libdrasyl.drasyl_node_opts_builder_min_pow_difficulty.argtypes = [
        c_void_p,  # builder
        c_uint8    # min_pow_difficulty
    ]
    _libdrasyl.drasyl_node_opts_builder_min_pow_difficulty.restype = c_int

    ensure_success(_libdrasyl.drasyl_node_opts_builder_min_pow_difficulty(builder, min_pow_difficulty))

@validate_ctypes()
@check_not_none()
def drasyl_node_opts_builder_hello_timeout(builder: c_void_p, hello_timeout: c_uint64):
    # Set argument and return types for the Rust FFI function
    _libdrasyl.drasyl_node_opts_builder_hello_timeout.argtypes = [
        c_void_p,  # builder
        c_uint64   # hello_timeout
    ]
    _libdrasyl.drasyl_node_opts_builder_hello_timeout.restype = c_int

    ensure_success(_libdrasyl.drasyl_node_opts_builder_min_pow_difficulty(builder, hello_timeout))

@validate_ctypes()
@check_not_none()
def drasyl_node_opts_builder_hello_max_age(builder: c_void_p, hello_max_age: c_uint64):
    # Set argument and return types for the Rust FFI function
    _libdrasyl.drasyl_node_opts_builder_hello_max_age.argtypes = [
        c_void_p,  # builder
        c_uint64   # hello_max_age
    ]
    _libdrasyl.drasyl_node_opts_builder_hello_max_age.restype = c_int

    ensure_success(_libdrasyl.drasyl_node_opts_builder_hello_max_age(builder, hello_max_age))
