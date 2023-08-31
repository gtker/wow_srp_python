# `wow_srp` for Python

SRP6 library for Python that supports WoW version 1.2 through to 3.3.5.

This is just a Python wrapper [around the original `wow_srp` library](https://github.com/gtker/wow_srp).

# Installation

Install from [PyPI](https://pypi.org/project/wow-srp/) with pip:

```bash
pip install wow-srp
```

# Usage

## Authentication

The module is split into functionality used by a server implementation and a client implementation.

### Server

```text
SrpVerifier -> SrpProof -> SrpServer
```

You will only want to save the username, salt, and password verifier for an account.
Do not save the raw passwords on the server.

Construct an `SrpVerifier` through

```python
>>> username = "A"
>>> password = "A"
>>> server = SrpVerifier.from_username_and_password(username, password)
>>> salt = server.salt()
>>> password_verifier = server.password_verifier()
```

Save the `username`, `salt`, and `password_verifier` in your database.

When a client connects, retrieve the `username`, `salt`, and `password_verifier` from your database and create
an `SrpVerifier` through the constructor and convert it to an `SrpProof`:

```python
>>> server = SrpVerifier(username, password_verifier, salt)
>>> server = server.into_proof()
```

The `salt`, `server_public_key`, `generator`, and `large_safe_prime` can then be sent to the client:
The internal calculations use the generator and large safe prime from the functions, and these MUST
be the ones sent to the client.

```python
>>> salt = server.salt()
>>> server_public_key = server.server_public_key()
>>> generator = generator()
>>> large_safe_prime = large_safe_prime()
```

After receiving the `client_public_key` and `client_proof`, the proof can be attempted converted to an `SrpServer`.

```python
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
```

The client is now logged in and can be sent the realm list.

If the client loses connection it will attempt to reconnect.
This requires a valid `SrpServer` to exist.
In my opinion the reconnect method is insecure since it uses the session key that can easily be deduced
by any third party and it should not be implemented in a production auth server.

```python
>>> client_challenge_data = [0] * 16 # Arbitrary data to show usage
>>> client_proof = [0] * 20 # Arbitrary data to show usage
>>> # reconnect_valid = server.verify_reconnection_attempt(client_challenge_data, client_proof)
```

### Client

```text
SrpClientUser -> SrpClientChallenge -> SrpClient | -> SrpClientReconnection
```
The `SrpClientReconnection` is just a data struct that contains reconnection values.

The client does not have to save any values except for the username and password.

```python
>>> username = "A"
>>> password = "A"
>>> client = SrpClientUser(username, password)
```

After getting the `generator`, `large_safe_prime`, `server_public_key`, and `salt` from the server,
the `SrpClientUser` can be converted into an `SrpClientChallenge`.

```python
>>> generator = 7
>>> large_safe_prime = [1] * 32
>>> server_public_key = [1] * 32
>>> salt = [0] * 32
>>> client = client.into_challenge(generator, large_safe_prime, server_public_key, salt)
```

The client can then verify that the server also has the correct password through the `server_proof`:
This creates an `SrpClient`.

```python
>>> server_proof = [0] * 20
>>> client = client.verify_server_proof(server_proof)
>>> if client is None:
...     print("Invalid password")
Invalid password
```

The `SrpClient` can attempt to reconnect using the `server_reconnect_data`:

```python
>>> server_reconnect_data = [0] * 16
>>> # reconnect_data = client.calculate_reconnect_values(server_reconnect_data)
```

And then access the reconnect values from `reconnect_data`:

```python
>>> # challenge_data = reconnect_data.challenge_data()
>>> # client_proof = reconnect_data.client_proof()
```

## Header Encryption

### Server

First, create a `ProofSeed` from for the version that you need:

```python
>>> server_seed = VanillaProofSeed()
>>> server_seed_value = server_seed.seed()
```

Then send the value to the client in
[SMSG_AUTH_CHALLENGE](https://gtker.com/wow_messages/docs/smsg_auth_challenge.html).

After receiving [CMSG_AUTH_SESSION](https://gtker.com/wow_messages/docs/cmsg_auth_session.html)
from the client, convert the proof to a `HeaderCrypto`.

```python
>>> # server_crypto = server_seed.into_server_header_crypto(username, session_key, client_proof, client_seed)
```

You can then encrypt and decrypt message headers with

```python
>>> # data = server_crypto.encrypt_server_header(size, opcode)
>>> # size, opcode = server_crypto.decrypt_client_header(data)
```

### Client

First, create a `ProofSeed` from for the version that you need:

```python
>>> client_seed = VanillaProofSeed()
>>> client_seed_value = client_seed.seed()
```

Then convert the seed to a `HeaderCrypto` using the seed received from
[SMSG_AUTH_CHALLENGE](https://gtker.com/wow_messages/docs/smsg_auth_challenge.html).

```python
>>> # client_proof, client_crypto = client_seed.into_client_header_crypto(username, session_key, server_seed)
```

Then send the `client_proof` and `client_seed_value` to the server through
[CMSG_AUTH_SESSION](https://gtker.com/wow_messages/docs/cmsg_auth_session.html).

You can then encrypt and decrypt message headers with

```python
>>> # data = client_crypto.encrypt_client_header(size, opcode)
>>> # size, opcode = client_crypto.decrypt_server_header(data)
```

# Development

```bash
pip install maturin
curl https://pyenv.run | bash

# For fish
set -U PYENV_ROOT "$HOME/.pyenv"
fish_add_path "$PYENV_ROOT/bin"

pyenv init - | source
pyenv install 3.10
pyenv virtualenv 3.10 pyo3
pyenv activate pyo3
maturin develop
```
