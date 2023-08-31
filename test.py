#!/usr/bin/env python3

import wow_srp
import unittest
import doctest

username = "A"
password = "A"
v1 = wow_srp.SrpVerifier.from_username_and_password(username, password)

salt = v1.salt()
password_verifier = v1.password_verifier()
v = wow_srp.SrpVerifier(username, password_verifier, salt)

assert len(v.salt()) == 32
assert len(v.password_verifier()) == 32
assert v.username() == username

p = v.into_proof()

assert len(p.salt()) == 32
assert len(p.server_public_key()) == 32

c = wow_srp.SrpClientChallenge(username, password, wow_srp.generator(), wow_srp.large_safe_prime(), p.server_public_key(), p.salt())

(s, proof) = p.into_server(c.client_public_key(), c.client_proof())

c = c.verify_server_proof(proof)

r = c.calculate_reconnect_values(s.reconnect_challenge_data())
assert s.verify_reconnection_attempt(r.challenge_data(), r.client_proof())

## Vanilla

server_seed = wow_srp.VanillaProofSeed()
server_seed_value = server_seed.seed()

client_seed = wow_srp.VanillaProofSeed()
client_seed_value = client_seed.seed()

proof, client_crypto = client_seed.into_client_header_crypto(username, c.session_key(), server_seed_value)

server_crypto = server_seed.into_server_header_crypto(username, s.session_key(), proof, client_seed_value)

data = server_crypto.encrypt_server_header(0x0102, 0x0403)
size, opcode = client_crypto.decrypt_server_header(data)

assert size == 0x0102
assert opcode == 0x0403

data = client_crypto.encrypt_client_header(0x0102, 0x06050403)
size, opcode = server_crypto.decrypt_client_header(data)

assert size == 0x0102
assert opcode == 0x06050403

## TBC

server_seed = wow_srp.TbcProofSeed()
server_seed_value = server_seed.seed()

client_seed = wow_srp.TbcProofSeed()
client_seed_value = client_seed.seed()

proof, client_crypto = client_seed.into_client_header_crypto(username, c.session_key(), server_seed_value)

server_crypto = server_seed.into_server_header_crypto(username, s.session_key(), proof, client_seed_value)

data = server_crypto.encrypt_server_header(0x0102, 0x0403)
size, opcode = client_crypto.decrypt_server_header(data)

assert size == 0x0102
assert opcode == 0x0403

data = client_crypto.encrypt_client_header(0x0102, 0x06050403)
size, opcode = server_crypto.decrypt_client_header(data)

assert size == 0x0102
assert opcode == 0x06050403

## wrath

server_seed = wow_srp.WrathProofSeed()
server_seed_value = server_seed.seed()

client_seed = wow_srp.WrathProofSeed()
client_seed_value = client_seed.seed()

proof, client_crypto = client_seed.into_client_header_crypto(username, c.session_key(), server_seed_value)

server_crypto = server_seed.into_server_header_crypto(username, s.session_key(), proof, client_seed_value)

data = server_crypto.encrypt_server_header(0x0102, 0x0403)
size, opcode = client_crypto.decrypt_server_header(data)

assert size == 0x0102
assert opcode == 0x0403

data = client_crypto.encrypt_client_header(0x0102, 0x06050403)
size, opcode = server_crypto.decrypt_client_header(data)

assert size == 0x0102
assert opcode == 0x06050403

# Better diagnostics compared to `doctest.testmod(wow_srp)`
testSuite = unittest.TestSuite()
testSuite.addTest(doctest.DocTestSuite(wow_srp))
result = unittest.TextTestRunner(verbosity=2).run(testSuite)
if not result.wasSuccessful():
    exit(1)

print("Tests passed")

