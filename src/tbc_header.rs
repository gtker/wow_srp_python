use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use wow_srp::normalized_string::NormalizedString;
use wow_srp::tbc_header::ProofSeed as InnerSeed;
use wow_srp::tbc_header::SERVER_HEADER_LENGTH;
use wow_srp::tbc_header::{HeaderCrypto as InnerCrypto, CLIENT_HEADER_LENGTH};
use wow_srp::{PROOF_LENGTH, SESSION_KEY_LENGTH};

#[pyclass]
pub struct TbcProofSeed {
    inner: InnerSeed,
}

#[pymethods]
impl TbcProofSeed {
    #[new]
    pub fn new() -> Self {
        Self {
            inner: InnerSeed::new(),
        }
    }

    pub fn seed(&self) -> u32 {
        self.inner.seed()
    }

    pub fn into_server_header_crypto(
        &self,
        username: &str,
        session_key: [u8; SESSION_KEY_LENGTH as _],
        client_proof: [u8; PROOF_LENGTH as _],
        client_seed: u32,
    ) -> PyResult<TbcHeaderCrypto> {
        let s = self.inner.clone();

        let Ok(username) = NormalizedString::new(username) else {
            return Err(PyValueError::new_err(
                "username contains invalid characters",
            ));
        };

        let Ok(inner) = s.into_header_crypto(&username, session_key, client_proof, client_seed)
        else {
            return Err(PyValueError::new_err("proofs do not match"));
        };

        Ok(TbcHeaderCrypto { inner })
    }

    pub fn into_client_header_crypto(
        &self,
        username: &str,
        session_key: [u8; SESSION_KEY_LENGTH as _],
        server_seed: u32,
    ) -> PyResult<([u8; PROOF_LENGTH as _], TbcHeaderCrypto)> {
        let s = self.inner.clone();

        let Ok(username) = NormalizedString::new(username) else {
            return Err(PyValueError::new_err(
                "username contains invalid characters",
            ));
        };

        let (proof, inner) = s.into_proof_and_header_crypto(&username, session_key, server_seed);

        Ok((proof, TbcHeaderCrypto { inner }))
    }
}

#[pyclass]
pub struct TbcHeaderCrypto {
    inner: InnerCrypto,
}

#[pymethods]
impl TbcHeaderCrypto {
    pub fn decrypt_server_header(&mut self, data: [u8; SERVER_HEADER_LENGTH as _]) -> (u16, u16) {
        let h = self.inner.decrypt_server_header(data);

        (h.size, h.opcode)
    }

    pub fn encrypt_server_header(
        &mut self,
        size: u16,
        opcode: u16,
    ) -> [u8; SERVER_HEADER_LENGTH as _] {
        let data = self.inner.encrypt_server_header(size, opcode);

        data
    }

    pub fn decrypt_client_header(&mut self, data: [u8; CLIENT_HEADER_LENGTH as _]) -> (u16, u32) {
        let h = self.inner.decrypt_client_header(data);

        (h.size, h.opcode)
    }

    pub fn encrypt_client_header(
        &mut self,
        size: u16,
        opcode: u32,
    ) -> [u8; CLIENT_HEADER_LENGTH as _] {
        let data = self.inner.encrypt_client_header(size, opcode);

        data
    }
}
