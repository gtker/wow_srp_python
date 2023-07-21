use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use wow_srp::normalized_string::NormalizedString;
use wow_srp::server::SrpProof as InnerProof;
use wow_srp::server::SrpServer as InnerServer;
use wow_srp::server::SrpVerifier as InnerVerifier;
use wow_srp::{
    PublicKey, GENERATOR, LARGE_SAFE_PRIME_LENGTH, LARGE_SAFE_PRIME_LITTLE_ENDIAN,
    PASSWORD_VERIFIER_LENGTH, PROOF_LENGTH, PUBLIC_KEY_LENGTH, RECONNECT_CHALLENGE_DATA_LENGTH,
    SALT_LENGTH, SESSION_KEY_LENGTH,
};

/// Generator value used in the SRP6 calculation.
///
/// Called `g` in the official RFC and other literature.
#[pyfunction]
pub fn generator() -> u8 {
    GENERATOR
}

/// Large safe prime value used in the SRP6 calculation in **little endian**.
///
/// Called `N` in the official RFC and other literature.
///
/// :returns An 32 bit **little endian** array.
#[pyfunction]
pub fn large_safe_prime() -> [u8; LARGE_SAFE_PRIME_LENGTH as usize] {
    LARGE_SAFE_PRIME_LITTLE_ENDIAN
}

#[pyclass]
pub struct SrpVerifier {
    inner: InnerVerifier,
}

#[pymethods]
impl SrpVerifier {
    #[new]
    pub fn new(
        username: &str,
        password_verifier: [u8; PASSWORD_VERIFIER_LENGTH as usize],
        salt: [u8; SALT_LENGTH as usize],
    ) -> PyResult<Self> {
        let Ok(username) = NormalizedString::new(username) else {
            return Err(PyValueError::new_err("username contains invalid characters"));
        };

        Ok(Self {
            inner: InnerVerifier::from_database_values(username, password_verifier, salt),
        })
    }

    #[staticmethod]
    pub fn from_username_and_password(username: &str, password: &str) -> PyResult<Self> {
        let Ok(username) = NormalizedString::new(username) else {
            return Err(PyValueError::new_err("username contains invalid characters"));
        };
        let Ok(password) = NormalizedString::new(password) else {
            return Err(PyValueError::new_err("password contains invalid characters"));
        };

        Ok(Self {
            inner: InnerVerifier::from_username_and_password(username, password),
        })
    }

    pub fn into_proof(&self) -> SrpProof {
        // Python doesn't have a borrow checker so we can't take self :/
        let s = self.inner.clone();

        SrpProof {
            inner: s.into_proof(),
        }
    }

    pub fn salt(&self) -> [u8; SALT_LENGTH as usize] {
        *self.inner.salt()
    }

    pub fn password_verifier(&self) -> [u8; PASSWORD_VERIFIER_LENGTH as usize] {
        *self.inner.password_verifier()
    }

    pub fn username(&self) -> &str {
        self.inner.username()
    }
}

#[pyclass]
pub struct SrpProof {
    inner: InnerProof,
}

#[pymethods]
impl SrpProof {
    pub fn server_public_key(&self) -> [u8; PUBLIC_KEY_LENGTH as usize] {
        *self.inner.server_public_key()
    }

    pub fn salt(&self) -> [u8; SALT_LENGTH as usize] {
        *self.inner.salt()
    }

    pub fn into_server(
        &self,
        client_public_key: [u8; PUBLIC_KEY_LENGTH as usize],
        client_proof: [u8; PROOF_LENGTH as usize],
    ) -> PyResult<Option<(SrpServer, [u8; PROOF_LENGTH as usize])>> {
        let Ok(client_public_key) = PublicKey::from_le_bytes(client_public_key) else {
            return Err(PyValueError::new_err("invalid public key"));
        };

        // Python doesn't have a borrow checker so we can't take self :/
        let s = self.inner.clone();

        let Ok((inner, proof)) = s.into_server(client_public_key, client_proof) else {
            return Ok(None)
        };

        Ok(Some((SrpServer { inner }, proof)))
    }
}

#[pyclass]
pub struct SrpServer {
    inner: InnerServer,
}

#[pymethods]
impl SrpServer {
    pub fn session_key(&self) -> [u8; SESSION_KEY_LENGTH as usize] {
        *self.inner.session_key()
    }

    pub fn reconnect_challenge_data(&self) -> [u8; RECONNECT_CHALLENGE_DATA_LENGTH as usize] {
        *self.inner.reconnect_challenge_data()
    }

    pub fn verify_reconnection_attempt(
        &mut self,
        client_data: [u8; RECONNECT_CHALLENGE_DATA_LENGTH as usize],
        client_proof: [u8; PROOF_LENGTH as usize],
    ) -> bool {
        self.inner
            .verify_reconnection_attempt(client_data, client_proof)
    }
}
