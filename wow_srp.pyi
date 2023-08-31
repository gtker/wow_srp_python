"""
Module that implements the SRP6 algorithm as well as the message header encryptiong
used for World of Warcraft versions 1.0 through to 3.3.5.

# Authentication

The module is split into functionality used by a server implementation and a client implementation.

## Server

```
SrpVerifier -> SrpProof -> SrpServer
```

You will only want to save the username, salt, and password verifier for an account.
Do not save the raw passwords on the server.

Construct an `SrpVerifier` through

>>> username = "A"
>>> password = "A"
>>> server = SrpVerifier.from_username_and_password(username, password)
>>> salt = server.salt()
>>> password_verifier = server.password_verifier()

Save the `username`, `salt`, and `password_verifier` in your database.

When a client connects, retrieve the `username`, `salt`, and `password_verifier` from your database and create
an `SrpVerifier` through the constructor and convert it to an `SrpProof`:

>>> server = SrpVerifier(username, password_verifier, salt)
>>> server = server.into_proof()

The `salt`, `server_public_key`, `generator`, and `large_safe_prime` can then be sent to the client:
The internal calculations use the generator and large safe prime from the functions, and these MUST
be the ones sent to the client.

>>> salt = server.salt()
>>> server_public_key = server.server_public_key()
>>> generator = generator()
>>> large_safe_prime = large_safe_prime()

After receiving the `client_public_key` and `client_proof`, the proof can be attempted converted to an `SrpServer`.

>>> client_public_key = [1] * 32 # Arbitrary data to show usage
>>> client_proof = [0] * 20 # Arbitrary data to show usage
>>> try:
...    # Returns tuple of server, proof, but doctest will fail
...    server = server.into_server(client_public_key, client_proof)
... except:
...    print("Public key is invalid")
>>> if server is None:
...     print("Password was incorrect")
Password was incorrect

The client is now logged in and can be sent the realm list.

If the client loses connection it will attempt to reconnect.
This requires a valid `SrpServer` to exist.
In my opinion the reconnect method is insecure since it uses the session key that can easily be deduced
by any third party and it should not be implemented in a production auth server.

>>> client_challenge_data = [0] * 16 # Arbitrary data to show usage
>>> client_proof = [0] * 20 # Arbitrary data to show usage
>>> # reconnect_valid = server.verify_reconnection_attempt(client_challenge_data, client_proof)

## Client

```
SrpClientUser -> SrpClientChallenge -> SrpClient | -> SrpClientReconnection
```
The `SrpClientReconnection` is just a data struct that contains reconnection values.

The client does not have to save any values except for the username and password.

>>> username = "A"
>>> password = "A"
>>> client = SrpClientUser(username, password)

After getting the `generator`, `large_safe_prime`, `server_public_key`, and `salt` from the server,
the `SrpClientUser` can be converted into an `SrpClientChallenge`.

>>> generator = 7
>>> large_safe_prime = [1] * 32
>>> server_public_key = [1] * 32
>>> salt = [0] * 32
>>> client = client.into_challenge(generator, large_safe_prime, server_public_key, salt)

The client can then verify that the server also has the correct password through the `server_proof`:
This creates an `SrpClient`.

>>> server_proof = [0] * 20
>>> client = client.verify_server_proof(server_proof)
>>> if client is None:
...     print("Invalid password")
Invalid password

The `SrpClient` can attempt to reconnect using the `server_reconnect_data`:

>>> server_reconnect_data = [0] * 16
>>> # reconnect_data = client.calculate_reconnect_values(server_reconnect_data)

And then access the reconnect values from `reconnect_data`:

>>> # challenge_data = reconnect_data.challenge_data()
>>> # client_proof = reconnect_data.client_proof()

# Header Encryption

## Server

First, create a `ProofSeed` from for the version that you need:

>>> server_seed = vanilla_header.ProofSeed()
>>> server_seed_value = server_seed.seed()

Then send the value to the client in
[SMSG_AUTH_CHALLENGE](https://gtker.com/wow_messages/docs/smsg_auth_challenge.html).

After receiving [CMSG_AUTH_SESSION](https://gtker.com/wow_messages/docs/cmsg_auth_session.html)
from the client, convert the proof to a `HeaderCrypto`.

>>> # server_crypto = server_seed.into_server_header_crypto(username, session_key, client_proof, client_seed)

You can then encrypt and decrypt message headers with

>>> # data = server_crypto.encrypt_server_header(size, opcode)
>>> # size, opcode = server_crypto.decrypt_client_header(data)

## Client

First, create a `ProofSeed` from for the version that you need:

>>> client_seed = vanilla_header.ProofSeed()
>>> client_seed_value = client_seed.seed()

Then convert the seed to a `HeaderCrypto` using the seed received from
[SMSG_AUTH_CHALLENGE](https://gtker.com/wow_messages/docs/smsg_auth_challenge.html).

>>> # client_proof, client_crypto = client_seed.into_client_header_crypto(username, session_key, server_seed)

Then send the `client_proof` and `client_seed_value` to the server through
[CMSG_AUTH_SESSION](https://gtker.com/wow_messages/docs/cmsg_auth_session.html).

You can then encrypt and decrypt message headers with

>>> # data = client_crypto.encrypt_client_header(size, opcode)
>>> # size, opcode = client_crypto.decrypt_server_header(data)
"""

import typing

byte_type = typing.Union[bytes, list[int], bytearray]

def generator() -> int:
    """
    Generator value used in the SRP6 calculation.

    Called `g` in the official RFC and other literature.
    """
    ...

def large_safe_prime() -> list[int]:
    """
    Large safe prime value used in the SRP6 calculation in **little endian**.

    Called `N` in the official RFC and other literature.

    :returns An 32 bit **little endian** array.
    """
    ...

class SrpClient(object):
    # no doc
    def calculate_reconnect_values(self, server_challenge_data: byte_type) -> SrpClientReconnection:
        ...

    def session_key(self) -> list[int] : ...

class SrpClientChallenge(object):
    @staticmethod
    def __new__(cls, username: str, password: str, generator: int, large_safe_prime: byte_type, server_public_key: byte_type, salt: byte_type) -> SrpClientChallenge:
        """ Create and return a new object.  See help(type) for accurate signature. """
        ...

    def __init__(cls, username: str, password: str, generator: int, large_safe_prime: byte_type, server_public_key: byte_type, salt: byte_type) -> SrpClientChallenge:
        """ Create and return a new object.  See help(type) for accurate signature. """
        ...

    # no doc
    def client_proof(self) -> list[int]: ...

    def client_public_key(self) -> list[int]: ...

    def verify_server_proof(self, server_proof: byte_type): ...


class SrpClientReconnection(object):
    # no doc
    def challenge_data(self) -> list[int]: ...

    def client_proof(self) -> list[int]: ...


class SrpProof(object):
    # no doc
    def into_server(self, client_public_key: byte_type, client_proof: byte_type): ...

    def salt(self) -> list[int]: ...

    def server_public_key(self) -> list[int]: ...

class SrpServer(object):
    def reconnect_challenge_data(self) -> list[int]: ...

    def session_key(self) -> list[int]: ...

    def verify_reconnection_attempt(self, client_data: byte_type, client_proof: byte_type) -> bool: ...


class SrpVerifier(object):
    @staticmethod
    def from_username_and_password(username: str, password: str) -> SrpVerifier: ...

    def into_proof(self) -> SrpProof: ...

    def password_verifier(self) -> list[int]: ...

    def salt(self) -> list[int]: ...

    def username(self) -> str: ...

    def __init__(self, username: str, password_verifier: byte_type, salt: byte_type) -> SrpVerifier: ...

    @staticmethod
    def __new__(cls, username: str, password_verifier: byte_type, salt: byte_type) -> SrpVerifier:
        """ Create and return a new object.  See help(type) for accurate signature. """
        ...


class VanillaProofSeed(object):
    def __init__(self) -> VanillaProofSeed: ...

    @staticmethod
    def __new__(cls) -> VanillaProofSeed:
        """ Create and return a new object.  See help(type) for accurate signature. """
        ...

    def seed(self) -> int: ...

    def into_server_header_crypto(self, username: str, session_key: byte_type, client_proof: byte_type, client_seed: int) -> VanillaHeaderCrypto: ...

    def into_client_header_crypto(self, username: str, session_key: byte_type, server_seed: int) -> VanillaHeaderCrypto: ...

class VanillaHeaderCrypto(object):
    def decrypt_server_header(self, data: byte_type) -> (int, int): ...

    def encrypt_server_header(self, size: int, opcode: int) -> list[int]: ...

    def decrypt_client_header(self, data: byte_type) -> (int, int): ...

    def encrypt_client_header(self, size: int, opcode: int) -> list[int]: ...


class TbcProofSeed(object):
    def __init__(self) -> TbcProofSeed: ...

    @staticmethod
    def __new__(cls) -> TbcProofSeed:
        """ Create and return a new object.  See help(type) for accurate signature. """
        ...

    def seed(self) -> int: ...

    def into_server_header_crypto(self, username: str, session_key: byte_type, client_proof: byte_type, client_seed: int) -> TbcHeaderCrypto: ...

    def into_client_header_crypto(self, username: str, session_key: byte_type, server_seed: int) -> TbcHeaderCrypto: ...

class TbcHeaderCrypto(object):
    def decrypt_server_header(self, data: byte_type) -> (int, int): ...

    def encrypt_server_header(self, size: int, opcode: int) -> list[int]: ...

    def decrypt_client_header(self, data: byte_type) -> (int, int): ...

    def encrypt_client_header(self, size: int, opcode: int) -> list[int]: ...

class WrathProofSeed(object):
    def __init__(self) -> WrathProofSeed: ...

    @staticmethod
    def __new__(cls) -> WrathProofSeed:
        """ Create and return a new object.  See help(type) for accurate signature. """
        ...

    def seed(self) -> int: ...

    def into_server_header_crypto(self, username: str, session_key: byte_type, client_proof: byte_type, client_seed: int) -> WrathServerCrypto: ...

    def into_client_header_crypto(self, username: str, session_key: byte_type, server_seed: int) -> WrathClientCrypto: ...

class WrathServerCrypto(object):

    def encrypt_server_header(self, size: int, opcode: int) -> list[int]: ...

    def decrypt_client_header(self, data: byte_type) -> (int, int): ...

class WrathClientCrypto(object):
    def decrypt_server_header(self, data: byte_type) -> (int, int): ...
    def encrypt_client_header(self, size: int, opcode: int) -> list[int]: ...
