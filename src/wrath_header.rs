use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use wow_srp::normalized_string::NormalizedString;
use wow_srp::wrath_header::{
    ClientCrypto as InnerClientCrypto, ServerCrypto as InnerServerCrypto, CLIENT_HEADER_LENGTH,
};
use wow_srp::wrath_header::{
    ProofSeed as InnerSeed, SERVER_HEADER_MAXIMUM_LENGTH, SERVER_HEADER_MINIMUM_LENGTH,
};
use wow_srp::{PROOF_LENGTH, SESSION_KEY_LENGTH};

#[pyclass]
pub struct WrathProofSeed {
    inner: InnerSeed,
}

#[pymethods]
impl WrathProofSeed {
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
    ) -> PyResult<WrathServerCrypto> {
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

        Ok(WrathServerCrypto { inner })
    }

    pub fn into_client_header_crypto(
        &self,
        username: &str,
        session_key: [u8; SESSION_KEY_LENGTH as _],
        server_seed: u32,
    ) -> PyResult<([u8; PROOF_LENGTH as _], WrathClientCrypto)> {
        let s = self.inner.clone();

        let Ok(username) = NormalizedString::new(username) else {
            return Err(PyValueError::new_err(
                "username contains invalid characters",
            ));
        };

        let (proof, inner) = s.into_proof_and_header_crypto(&username, session_key, server_seed);

        Ok((proof, WrathClientCrypto { inner }))
    }
}

#[pyclass]
pub struct WrathServerCrypto {
    inner: InnerServerCrypto,
}

#[pymethods]
impl WrathServerCrypto {
    pub fn encrypt_server_header(&mut self, size: u32, opcode: u16) -> Vec<u8> {
        let mut v = Vec::with_capacity(SERVER_HEADER_MAXIMUM_LENGTH as _);

        self.inner
            .write_encrypted_server_header(&mut v, size, opcode)
            .unwrap();

        v
    }

    pub fn decrypt_client_header(&mut self, data: [u8; CLIENT_HEADER_LENGTH as _]) -> (u16, u32) {
        let h = self.inner.decrypt_client_header(data);

        (h.size, h.opcode)
    }
}

#[pyclass]
pub struct WrathClientCrypto {
    inner: InnerClientCrypto,
}

#[pymethods]
impl WrathClientCrypto {
    pub fn decrypt_server_header(&mut self, data: Vec<u8>) -> PyResult<(u32, u16)> {
        let data: [u8; SERVER_HEADER_MAXIMUM_LENGTH as _] =
            if data.len() == SERVER_HEADER_MAXIMUM_LENGTH as usize {
                data.try_into().unwrap()
            } else if data.len() == SERVER_HEADER_MINIMUM_LENGTH as usize {
                let mut d = [0_u8; SERVER_HEADER_MAXIMUM_LENGTH as usize];

                for (i, b) in data.iter().enumerate() {
                    d[i] = *b;
                }

                d
            } else {
                return Err(PyValueError::new_err("data length is invalid"));
            };

        let h = self.inner.decrypt_server_header(&data);

        Ok((h.size, h.opcode))
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
