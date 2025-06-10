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
# utilities
#

class _dotdict(dict):
    """dot.notation access to dictionary attributes"""
    __getattr__ = dict.get
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__

def _wrap_event(event):
    response = {
        'event_code': event[0].event_code
    }

    if 10 <= event[0].event_code and event[0].event_code <= 15:
        response['node'] = _dotdict({
            'identity': _dotdict({
                'proof_of_work': event[0].node[0].identity[0].proof_of_work,
                'identity_public_key': event[0].node[0].identity[0].identity_public_key.decode('UTF-8'),
                'identity_secret_key': event[0].node[0].identity[0].identity_secret_key.decode('UTF-8')
            })
        })
    elif 20 <= event[0].event_code and event[0].event_code <= 23:
        response['peer'] = _dotdict({
            'address': event[0].peer[0].address.decode('UTF-8')
        })
    elif event[0].event_code == 30:
        response['sender'] = event[0].message_sender.decode('UTF-8')
        response['payload'] = event[0].message_payload.decode('UTF-8')

    return _dotdict(response)

#
# drasyl API
#

DRASYL_LOG_TRACE = 300
DRASYL_LOG_DEBUG = 500
DRASYL_LOG_INFO = 800
DRASYL_LOG_WARN = 900
DRASYL_LOG_ERROR = 1000

# Signals that the node has been started
DRASYL_EVENT_NODE_UP = 10
# Signals that the node is shut down
DRASYL_EVENT_NODE_DOWN = 11
# Signals that the node is currently connected to a super peer
DRASYL_EVENT_NODE_ONLINE = 12
# Signals that the node is currently not connected to a super peer
DRASYL_EVENT_NODE_OFFLINE = 13
# Signals that the node encountered an unrecoverable error
DRASYL_EVENT_NODE_UNRECOVERABLE_ERROR = 14
# Signals that the node has terminated normally
DRASYL_EVENT_NODE_NORMAL_TERMINATION = 15
# Signals that the node has established a direct connection to a peer
DRASYL_EVENT_PEER_DIRECT = 20
# Signals that communication with this peer is only possible by relaying messages via a super peer
DRASYL_EVENT_PEER_RELAY = 21
# Signals that currently all messages from and to the peer are encrypted with a long time key
DRASYL_EVENT_LONG_TIME_ENCRYPTION = 22
# Signals that currently all messages from and to the {@code #peer} are encrypted with an ephemeral session key
DRASYL_EVENT_PERFECT_FORWARD_SECRECY_ENCRYPTION = 23
# Signals that the node has received a message addressed to it
DRASYL_EVENT_MESSAGE = 30
# Signals that the node was unable to process an inbound message
DRASYL_EVENT_INBOUND_EXCEPTION = 40

# === Constants matching Rust definitions ===
ED25519_SECRETKEYBYTES = 64
ED25519_PUBLICKEYBYTES = 32
POW_BYTES = 4

_libdrasyl.drasyl_version.restype = c_char_p
def drasyl_version():
    version = _libdrasyl.drasyl_version()
    return version.decode("utf-8").strip("\0")

def drasyl_generate_identity():
    """
Calls the Rust `generate_identity` function and returns
the generated secret key, public key, and proof of work as bytes.

Returns:
tuple(bytes, bytes, bytes): (secret_key, public_key, proof_of_work)

Raises:
RuntimeError: If the Rust function returns an error code.
    """

    # Set argument and return types for the Rust FFI function
    _libdrasyl.generate_identity.argtypes = [
        POINTER(c_ubyte),  # secret key buffer
        POINTER(c_ubyte),  # public key buffer
        POINTER(c_ubyte),  # proof of work buffer
    ]
    _libdrasyl.generate_identity.restype = c_int

    # Allocate buffers for the output data
    sk = (c_ubyte * ED25519_SECRETKEYBYTES)()
    pk = (c_ubyte * ED25519_PUBLICKEYBYTES)()
    pow_buf = (c_ubyte * POW_BYTES)()

    # Call the Rust function
    result = _libdrasyl.generate_identity(sk, pk, pow_buf)

    # Handle possible error codes from Rust
    if result == 1:
        raise RuntimeError("Null pointer passed to generate_identity()")
    elif result == 2:
        raise RuntimeError("Identity generation failed")
    elif result != 0:
        raise RuntimeError(f"Unknown error code returned: {result}")

    # Return the results as Python bytes objects
    return bytes(sk), bytes(pk), bytes(pow_buf)


def parse_identity(identity_tuple):
    sk_bytes, pk_bytes, pow_bytes = identity_tuple
    sk_hex = sk_bytes.hex()
    pk_hex = pk_bytes.hex()
    pow_int = int.from_bytes(pow_bytes, byteorder='big', signed=True)
    return sk_hex, pk_hex, pow_int