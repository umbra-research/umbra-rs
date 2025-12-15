use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use thiserror::Error;

#[cfg(feature = "logging")]
use tracing::{debug, warn};

/// Result alias for storage operations.
pub type Result<T> = std::result::Result<T, StorageError>;

/// Errors emitted by the storage layer.
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Supported networks to disambiguate state files.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Network {
    Local,
    Devnet,
    MainnetBeta,
    /// Custom identifier (e.g. test validator instance).
    Custom(String),
}

impl Default for Network {
    fn default() -> Self {
        Network::Local
    }
}

/// User-defined knobs used while scanning.
pub type ScanParameters = BTreeMap<String, String>;

/// Progress marker for slot scanning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanState {
    pub last_scanned_slot: u64,
    pub network: Network,
    pub params: ScanParameters,
}

impl Default for ScanState {
    fn default() -> Self {
        Self {
            last_scanned_slot: 0,
            network: Network::default(),
            params: ScanParameters::new(),
        }
    }
}

/// Key for a deduplicated candidate output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct CandidateKey {
    pub slot: u64,
    pub signature: String,
}

impl CandidateKey {
    pub fn new(slot: u64, signature: impl Into<String>) -> Self {
        Self {
            slot,
            signature: signature.into(),
        }
    }
}

/// Raw candidate output captured during scanning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateRecord {
    pub slot: u64,
    pub signature: String,
    pub recipient: String,
    pub amount: u64,
    /// Memo bytes (uninterpreted).
    pub memo: Vec<u8>,
}

/// Verified output belonging to the claimant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnedOutputRecord {
    pub slot: u64,
    pub signature: String,
    pub one_time_pubkey: String,
    pub amount: u64,
    pub memo: Vec<u8>,
    /// Optional derived metadata for higher layers.
    pub metadata: BTreeMap<String, String>,
}

/// Sweep lifecycle state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SweepStatus {
    Planned,
    Submitted { tx_signature: String },
    Confirmed { tx_signature: String },
}

/// Tracking entry for sweeps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SweepRecord {
    pub output_signature: String,
    pub status: SweepStatus,
    pub last_updated_slot: Option<u64>,
}

/// Complete snapshot of Umbra state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UmbraState {
    pub scan: ScanState,
    pub candidates: BTreeMap<CandidateKey, CandidateRecord>,
    pub owned: BTreeMap<String, OwnedOutputRecord>,
    pub sweeps: BTreeMap<String, SweepRecord>,
}

impl Default for UmbraState {
    fn default() -> Self {
        Self {
            scan: ScanState::default(),
            candidates: BTreeMap::new(),
            owned: BTreeMap::new(),
            sweeps: BTreeMap::new(),
        }
    }
}

impl UmbraState {
    /// Deterministic serialization to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(serde_json::from_slice(bytes)?)
    }

    /// Convenient constructor that sets the target network.
    pub fn new_for_network(network: Network) -> Self {
        let mut scan = ScanState::default();
        scan.network = network;
        Self {
            scan,
            ..Default::default()
        }
    }
}

/// Summary of pruning work.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PruneReport {
    pub removed_candidates: usize,
    pub removed_owned: usize,
    pub removed_sweeps: usize,
}

/// Storage interface decoupled from RPC / crypto layers.
pub trait UmbraStorage: Send + Sync {
    fn load_state(&self) -> UmbraState;
    fn update_scan_state(
        &self,
        last_scanned_slot: u64,
        params: Option<ScanParameters>,
    ) -> Result<()>;
    fn save_candidate_output(&self, candidate: CandidateRecord) -> Result<bool>;
    fn promote_candidate_to_owned(
        &self,
        key: &CandidateKey,
        owned: OwnedOutputRecord,
    ) -> Result<bool>;
    fn mark_swept(
        &self,
        output_signature: &str,
        tx_signature: String,
        confirmed: bool,
    ) -> Result<()>;
    fn prune_old_or_spent_outputs(&self, min_slot: u64) -> Result<PruneReport>;
}

fn unwrap_poison<T>(lock: std::sync::LockResult<T>) -> T {
    match lock {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// In-memory backend optimized for speed.
#[derive(Clone)]
pub struct InMemoryStorage {
    state: Arc<RwLock<UmbraState>>,
}

impl InMemoryStorage {
    pub fn new(network: Network) -> Self {
        Self {
            state: Arc::new(RwLock::new(UmbraState::new_for_network(network))),
        }
    }

    pub fn from_state(state: UmbraState) -> Self {
        Self {
            state: Arc::new(RwLock::new(state)),
        }
    }

    fn with_write<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&mut UmbraState) -> T,
    {
        let mut guard = unwrap_poison(self.state.write());
        f(&mut guard)
    }
}

impl UmbraStorage for InMemoryStorage {
    fn load_state(&self) -> UmbraState {
        unwrap_poison(self.state.read()).clone()
    }

    fn update_scan_state(
        &self,
        last_scanned_slot: u64,
        params: Option<ScanParameters>,
    ) -> Result<()> {
        self.with_write(|state| {
            state.scan.last_scanned_slot = last_scanned_slot;
            if let Some(p) = params {
                state.scan.params = p;
            }
        });
        Ok(())
    }

    fn save_candidate_output(&self, candidate: CandidateRecord) -> Result<bool> {
        let key = CandidateKey::new(candidate.slot, candidate.signature.clone());
        let inserted = self.with_write(|state| {
            if state.candidates.contains_key(&key) || state.owned.contains_key(&candidate.signature)
            {
                false
            } else {
                state.candidates.insert(key, candidate);
                true
            }
        });
        Ok(inserted)
    }

    fn promote_candidate_to_owned(
        &self,
        key: &CandidateKey,
        owned: OwnedOutputRecord,
    ) -> Result<bool> {
        let moved = self.with_write(|state| {
            if state.candidates.remove(key).is_some() {
                state.owned.insert(owned.signature.clone(), owned);
                true
            } else {
                false
            }
        });
        Ok(moved)
    }

    fn mark_swept(
        &self,
        output_signature: &str,
        tx_signature: String,
        confirmed: bool,
    ) -> Result<()> {
        self.with_write(|state| {
            let status = if confirmed {
                SweepStatus::Confirmed {
                    tx_signature: tx_signature.clone(),
                }
            } else {
                SweepStatus::Submitted {
                    tx_signature: tx_signature.clone(),
                }
            };

            let entry = state
                .sweeps
                .entry(output_signature.to_string())
                .or_insert(SweepRecord {
                    output_signature: output_signature.to_string(),
                    status: SweepStatus::Planned,
                    last_updated_slot: None,
                });

            entry.status = status;
            entry.last_updated_slot = state.owned.get(output_signature).map(|o| o.slot);
        });
        Ok(())
    }

    fn prune_old_or_spent_outputs(&self, min_slot: u64) -> Result<PruneReport> {
        let mut report = PruneReport::default();

        self.with_write(|state| {
            let before = state.candidates.len();
            state.candidates.retain(|key, _| key.slot >= min_slot);
            report.removed_candidates = before - state.candidates.len();

            let before_owned = state.owned.len();
            state.owned.retain(|sig, owned| {
                if owned.slot < min_slot {
                    return false;
                }
                match state.sweeps.get(sig) {
                    Some(SweepRecord {
                        status: SweepStatus::Confirmed { .. },
                        ..
                    }) => false,
                    _ => true,
                }
            });
            report.removed_owned = before_owned - state.owned.len();

            let before_sweeps = state.sweeps.len();
            state.sweeps.retain(|sig, sweep| {
                sweep.last_updated_slot.unwrap_or(0) >= min_slot || state.owned.contains_key(sig)
            });
            report.removed_sweeps = before_sweeps - state.sweeps.len();
        });

        Ok(report)
    }
}

/// Disk-backed JSON storage with atomic writes.
pub struct JsonFileStorage {
    path: PathBuf,
    inner: InMemoryStorage,
    auto_flush: bool,
}

impl JsonFileStorage {
    /// Load state from disk or initialize a new one for the given network.
    pub fn load_or_init(path: impl AsRef<Path>, network: Network) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let state = if path.exists() {
            let bytes = fs::read(&path)?;
            match UmbraState::from_bytes(&bytes) {
                Ok(s) => s,
                Err(e) => {
                    #[cfg(feature = "logging")]
                    warn!("failed to parse state file ({}), starting fresh", e);
                    UmbraState::new_for_network(network.clone())
                }
            }
        } else {
            UmbraState::new_for_network(network.clone())
        };

        Ok(Self {
            path,
            inner: InMemoryStorage::from_state(state),
            auto_flush: true,
        })
    }

    /// Persist the current in-memory snapshot to disk.
    pub fn flush(&self) -> Result<()> {
        let snapshot = self.inner.load_state();
        let bytes = snapshot.to_bytes()?;

        let tmp_path = self.path.with_extension("tmp");
        {
            let mut file = File::create(&tmp_path)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        fs::rename(&tmp_path, &self.path)?;

        #[cfg(feature = "logging")]
        debug!("persisted Umbra state to {:?}", self.path);

        Ok(())
    }

    /// Disable automatic flush for bulk updates.
    pub fn with_manual_flush(mut self) -> Self {
        self.auto_flush = false;
        self
    }

    fn maybe_flush(&self) -> Result<()> {
        if self.auto_flush {
            self.flush()
        } else {
            Ok(())
        }
    }
}

impl UmbraStorage for JsonFileStorage {
    fn load_state(&self) -> UmbraState {
        self.inner.load_state()
    }

    fn update_scan_state(
        &self,
        last_scanned_slot: u64,
        params: Option<ScanParameters>,
    ) -> Result<()> {
        self.inner.update_scan_state(last_scanned_slot, params)?;
        self.maybe_flush()
    }

    fn save_candidate_output(&self, candidate: CandidateRecord) -> Result<bool> {
        let inserted = self.inner.save_candidate_output(candidate)?;
        if inserted {
            self.maybe_flush()?;
        }
        Ok(inserted)
    }

    fn promote_candidate_to_owned(
        &self,
        key: &CandidateKey,
        owned: OwnedOutputRecord,
    ) -> Result<bool> {
        let moved = self.inner.promote_candidate_to_owned(key, owned)?;
        if moved {
            self.maybe_flush()?;
        }
        Ok(moved)
    }

    fn mark_swept(
        &self,
        output_signature: &str,
        tx_signature: String,
        confirmed: bool,
    ) -> Result<()> {
        self.inner
            .mark_swept(output_signature, tx_signature, confirmed)?;
        self.maybe_flush()
    }

    fn prune_old_or_spent_outputs(&self, min_slot: u64) -> Result<PruneReport> {
        let report = self.inner.prune_old_or_spent_outputs(min_slot)?;
        if report.removed_candidates + report.removed_owned + report.removed_sweeps > 0 {
            self.maybe_flush()?;
        }
        Ok(report)
    }
}
