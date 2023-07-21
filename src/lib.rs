mod client;
mod server;

use pyo3::prelude::*;

/// Module that implements the SRP6 algorithm used for World of Warcraft versions 1.0 through to 3.3.5.
///
/// The module is split into functionality used by a server implementation and a client implementation.
///
/// # Server
///
/// ```
/// SrpVerifier -> SrpProof -> SrpServer
/// ```
///
/// You will only want to save the username, salt, and password verifier for an account.
/// Do not save the raw passwords on the server.
///
/// Construct an `SrpVerifier` through
///
/// >>> username = "A"
/// >>> password = "A"
/// >>> server = SrpVerifier.from_username_and_password(username, password)
/// >>> salt = server.salt()
/// >>> password_verifier = server.password_verifier()
///
/// Save the `username`, `salt`, and `password_verifier` in your database.
///
/// When a client connects, retrieve the `username`, `salt`, and `password_verifier` from your database and create
/// an `SrpVerifier` through the constructor and convert it to an `SrpProof`:
///
/// >>> server = SrpVerifier(username, password_verifier, salt)
/// >>> server = server.into_proof()
///
/// The `salt`, `server_public_key`, `generator`, and `large_safe_prime` can then be sent to the client:
/// The internal calculations use the generator and large safe prime from the functions, and these MUST
/// be the ones sent to the client.
///
/// >>> salt = server.salt()
/// >>> server_public_key = server.server_public_key()
/// >>> generator = generator()
/// >>> large_safe_prime = large_safe_prime()
///
/// After receiving the `client_public_key` and `client_proof`, the proof can be attempted converted to an `SrpServer`.
///
/// >>> client_public_key = [1] * 32 # Arbitrary data to show usage
/// >>> client_proof = [0] * 20 # Arbitrary data to show usage
/// >>> try:
/// ...    # Returns tuple of server, proof, but doctest will fail
/// ...    server = server.into_server(client_public_key, client_proof)
/// ... except:
/// ...    print("Public key is invalid")
/// >>> if server is None:
/// ...     print("Password was incorrect")
/// Password was incorrect
///
/// The client is now logged in and can be sent the realm list.
///
/// If the client loses connection it will attempt to reconnect.
/// This requires a valid `SrpServer` to exist.
/// In my opinion the reconnect method is insecure since it uses the session key that can easily be deduced
/// by any third party and it should not be implemented in a production auth server.
///
/// >>> client_challenge_data = [0] * 16 # Arbitrary data to show usage
/// >>> client_proof = [0] * 20 # Arbitrary data to show usage
/// >>> # reconnect_valid = server.verify_reconnection_attempt(client_challenge_data, client_proof)
///
/// # Client
///
/// ```
/// SrpClientUser -> SrpClientChallenge -> SrpClient | -> SrpClientReconnection
/// ```
/// The `SrpClientReconnection` is just a data struct that contains reconnection values.
///
/// The client does not have to save any values except for the username and password.
///
/// >>> username = "A"
/// >>> password = "A"
/// >>> client = SrpClientUser(username, password)
///
/// After getting the `generator`, `large_safe_prime`, `server_public_key`, and `salt` from the server,
/// the `SrpClientUser` can be converted into an `SrpClientChallenge`.
///
/// >>> generator = 7
/// >>> large_safe_prime = [1] * 32
/// >>> server_public_key = [1] * 32
/// >>> salt = [0] * 32
/// >>> client = client.into_challenge(generator, large_safe_prime, server_public_key, salt)
///
/// The client can then verify that the server also has the correct password through the `server_proof`:
/// This creates an `SrpClient`.
///
/// >>> server_proof = [0] * 20
/// >>> client = client.verify_server_proof(server_proof)
/// >>> if client is None:
/// ...     print("Invalid password")
/// Invalid password
///
/// The `SrpClient` can attempt to reconnect using the `server_reconnect_data`:
///
/// >>> server_reconnect_data = [0] * 16
/// >>> # reconnect_data = client.calculate_reconnect_values(server_reconnect_data)
///
/// And then access the reconnect values from `reconnect_data`:
///
/// >>> # challenge_data = reconnect_data.challenge_data()
/// >>> # client_proof = reconnect_data.client_proof()
///
#[pymodule]
fn wow_srp(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(server::generator, m)?)?;
    m.add_function(wrap_pyfunction!(server::large_safe_prime, m)?)?;

    m.add_class::<server::SrpVerifier>()?;
    m.add_class::<server::SrpProof>()?;
    m.add_class::<server::SrpServer>()?;

    m.add_class::<client::SrpClientUser>()?;
    m.add_class::<client::SrpClient>()?;
    m.add_class::<client::SrpClientChallenge>()?;
    m.add_class::<client::SrpClientReconnection>()?;

    Ok(())
}
