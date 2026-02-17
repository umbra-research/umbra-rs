use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScalarWrapper(pub Scalar);

impl Zeroize for ScalarWrapper {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for ScalarWrapper {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// ---------- Serialize ----------
impl Serialize for ScalarWrapper {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.0.to_bytes();
        serializer.serialize_bytes(&bytes)
    }
}

// ---------- Deserialize ----------
impl<'de> Deserialize<'de> for ScalarWrapper {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: &[u8] = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(D::Error::custom("invalid scalar length"));
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);

        Ok(ScalarWrapper(Scalar::from_bytes_mod_order(arr)))
    }
}

impl ScalarWrapper {
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        ScalarWrapper(Scalar::from_bytes_mod_order_wide(&bytes))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        ScalarWrapper(Scalar::from_bytes_mod_order(bytes))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

// Manual Borsh implementation to just write 32 bytes
use borsh::{BorshDeserialize, BorshSerialize};
use std::io::{Result as IoResult, Write};

impl BorshSerialize for ScalarWrapper {
    fn serialize<W: Write>(&self, writer: &mut W) -> IoResult<()> {
        let bytes = self.to_bytes();
        writer.write_all(&bytes)
    }
}

impl BorshDeserialize for ScalarWrapper {
    fn deserialize(buf: &mut &[u8]) -> IoResult<Self> {
        if buf.len() < 32 {
             return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "ScalarWrapper expects 32 bytes",
            ));
        }
        let (bytes, remaining) = buf.split_at(32);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        *buf = remaining;
        
        Ok(ScalarWrapper::from_bytes(arr))
    }

    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> IoResult<Self> {
        let mut buf = [0u8; 32];
        reader.read_exact(&mut buf)?;
        Ok(ScalarWrapper::from_bytes(buf))
    }
}
