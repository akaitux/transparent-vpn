use std::cmp::Ordering;

use tokio::time::Instant;
use trust_dns_server::client::rr::{LowerName, RecordType};

/// Accessor key for RRSets in the Authority.
#[derive(Eq, PartialEq, Debug, Hash, Clone)]
pub struct TRrKey {
    /// Matches the name in the Record of this key
    pub name: LowerName,
    /// Matches the type of the Record of this key
    pub record_type: RecordType,
    pub resolved_at: Option<Instant>,
}

impl TRrKey {
    pub fn new(name: LowerName, record_type: RecordType) -> Self {
        Self {
            name,
            record_type,
            resolved_at: None,
        }
    }

    /// Returns the name of the key
    pub fn name(&self) -> &LowerName {
        &self.name
    }
}

impl PartialOrd for TRrKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TRrKey {
    fn cmp(&self, other: &Self) -> Ordering {
        let order = self.name.cmp(&other.name);
        if order == Ordering::Equal {
            self.record_type.cmp(&other.record_type)
        } else {
            order
        }
    }
}
