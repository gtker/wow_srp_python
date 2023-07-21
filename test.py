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

c = wow_srp.SrpClientUser(username, password)
c = c.into_challenge(wow_srp.generator(), wow_srp.large_safe_prime(), p.server_public_key(), p.salt())

(s, proof) = p.into_server(c.client_public_key(), c.client_proof())

c = c.verify_server_proof(proof)

r = c.calculate_reconnect_values(s.reconnect_challenge_data())
assert s.verify_reconnection_attempt(r.challenge_data(), r.client_proof())


# Better diagnostics compared to `doctest.testmod(wow_srp)`
testSuite = unittest.TestSuite()
testSuite.addTest(doctest.DocTestSuite(wow_srp))
result = unittest.TextTestRunner(verbosity=2).run(testSuite)
if not result.wasSuccessful():
    exit(1)

print("Tests passed")

