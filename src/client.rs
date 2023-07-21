use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use wow_srp::client::SrpClient as InnerClient;
use wow_srp::client::SrpClientChallenge as InnerClientChallenge;
use wow_srp::client::SrpClientReconnection as InnerClientReconnection;
use wow_srp::client::SrpClientUser as InnerClientUser;
use wow_srp::normalized_string::NormalizedString;
use wow_srp::{
    PublicKey, LARGE_SAFE_PRIME_LENGTH, PROOF_LENGTH, PUBLIC_KEY_LENGTH,
    RECONNECT_CHALLENGE_DATA_LENGTH, SALT_LENGTH, SESSION_KEY_LENGTH,
};

#[pyclass]
pub struct SrpClientUser {
    inner: InnerClientUser,
}

#[pymethods]
impl SrpClientUser {
    #[new]
    pub fn new(username: &str, password: &str) -> PyResult<Self> {
        let Ok(username) = NormalizedString::new(username) else {
            return Err(PyValueError::new_err("username contains invalid characters"));
        };
        let Ok(password) = NormalizedString::new(password) else {
            return Err(PyValueError::new_err("password contains invalid characters"));
        };

        Ok(Self {
            inner: InnerClientUser::new(username, password),
        })
    }

    pub fn into_challenge(
        &self,
        generator: u8,
        large_safe_prime: [u8; LARGE_SAFE_PRIME_LENGTH as usize],
        server_public_key: [u8; PUBLIC_KEY_LENGTH as usize],
        salt: [u8; SALT_LENGTH as usize],
    ) -> PyResult<SrpClientChallenge> {
        let Ok(server_public_key) = PublicKey::from_le_bytes(server_public_key) else {
            return Err(PyValueError::new_err("invalid public key"));
        };

        let s = self.inner.clone();

        Ok(SrpClientChallenge {
            inner: s.into_challenge(generator, large_safe_prime, server_public_key, salt),
        })
    }
}

#[pyclass]
pub struct SrpClientChallenge {
    inner: InnerClientChallenge,
}

#[pymethods]
impl SrpClientChallenge {
    pub fn client_proof(&self) -> [u8; PROOF_LENGTH as usize] {
        *self.inner.client_proof()
    }

    pub fn client_public_key(&self) -> [u8; PUBLIC_KEY_LENGTH as usize] {
        *self.inner.client_public_key()
    }

    pub fn verify_server_proof(
        &self,
        server_proof: [u8; PROOF_LENGTH as usize],
    ) -> Option<SrpClient> {
        let s = self.inner.clone();

        let Ok(inner) = s.verify_server_proof(server_proof) else {
            return None;
        };

        Some(SrpClient { inner })
    }
}

#[pyclass]
pub struct SrpClient {
    inner: InnerClient,
}

#[pymethods]
impl SrpClient {
    pub fn session_key(&self) -> [u8; SESSION_KEY_LENGTH as usize] {
        self.inner.session_key()
    }

    pub fn calculate_reconnect_values(
        &self,
        server_challenge_data: [u8; RECONNECT_CHALLENGE_DATA_LENGTH as usize],
    ) -> SrpClientReconnection {
        SrpClientReconnection {
            inner: self.inner.calculate_reconnect_values(server_challenge_data),
        }
    }
}

#[pyclass]
pub struct SrpClientReconnection {
    inner: InnerClientReconnection,
}

#[pymethods]
impl SrpClientReconnection {
    pub fn challenge_data(&self) -> [u8; RECONNECT_CHALLENGE_DATA_LENGTH as usize] {
        self.inner.challenge_data
    }

    pub fn client_proof(&self) -> [u8; PROOF_LENGTH as usize] {
        self.inner.proof
    }
}
