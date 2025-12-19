use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PointWrapper(pub EdwardsPoint);

impl PointWrapper {
    /// Serialize to 32-byte compressed Edwards-Y representation.
    pub fn to_bytes(self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }

    /// Construct from 32-byte compressed Edwards-Y representation.
    ///
    /// Returns `None` if the bytes do not represent a valid curve point.
    pub fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        CompressedEdwardsY(bytes).decompress().map(PointWrapper)
    }
}

impl Serialize for PointWrapper {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for PointWrapper {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: &[u8] = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(DeError::custom("PointWrapper expects 32 bytes"));
        }

        let mut buf = [0u8; 32];
        buf.copy_from_slice(bytes);

        PointWrapper::from_bytes(buf).ok_or_else(|| DeError::custom("invalid Edwards point"))
    }
}
