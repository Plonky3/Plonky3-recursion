use hashbrown::HashSet;

use crate::op::NpoTypeId;

/// Policy trait to gate non-primitive ops availability.
pub trait NonPrimPolicy {
    fn is_allowed(&self, op: NpoTypeId) -> bool;
}

/// Default profile: non-primitive ops are not supported.
pub struct DefaultProfile;

impl NonPrimPolicy for DefaultProfile {
    #[inline]
    fn is_allowed(&self, _op: NpoTypeId) -> bool {
        false
    }
}

/// Allow all non-primitive ops.
pub struct AllowAllProfile;

impl NonPrimPolicy for AllowAllProfile {
    #[inline]
    fn is_allowed(&self, _op: NpoTypeId) -> bool {
        true
    }
}

/// Runtime policy defining the list of allowed non-primitive ops.
pub struct RuntimeAllowlist {
    allowed: HashSet<NpoTypeId>,
}

impl RuntimeAllowlist {
    pub fn from_slice(ops: &[NpoTypeId]) -> Self {
        Self {
            allowed: ops.iter().cloned().collect(),
        }
    }

    pub fn insert(&mut self, op: NpoTypeId) {
        self.allowed.insert(op);
    }
}

impl NonPrimPolicy for RuntimeAllowlist {
    #[inline]
    fn is_allowed(&self, op: NpoTypeId) -> bool {
        self.allowed.contains(&op)
    }
}
