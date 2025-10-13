use hashbrown::HashSet;

use crate::op::NonPrimitiveOpType;

/// Policy trait to gate non-primitive ops availability.
pub trait NonPrimPolicy {
    fn is_allowed(&self, op: NonPrimitiveOpType) -> bool;
}

/// Default profile: non-primitive ops are not supported.
pub struct DefaultProfile;

impl NonPrimPolicy for DefaultProfile {
    #[inline]
    fn is_allowed(&self, _op: NonPrimitiveOpType) -> bool {
        false
    }
}

/// Allow all non-primitive ops.
pub struct AllowAllProfile;

impl NonPrimPolicy for AllowAllProfile {
    #[inline]
    fn is_allowed(&self, _op: NonPrimitiveOpType) -> bool {
        true
    }
}

/// Runtime policy defining the list of allowed non-primitive ops.
pub struct RuntimeAllowlist {
    allowed: HashSet<NonPrimitiveOpType>,
}

impl RuntimeAllowlist {
    pub fn from_slice(ops: &[NonPrimitiveOpType]) -> Self {
        Self {
            allowed: ops.iter().cloned().collect(),
        }
    }

    pub fn insert(&mut self, op: NonPrimitiveOpType) {
        self.allowed.insert(op);
    }
}

impl NonPrimPolicy for RuntimeAllowlist {
    #[inline]
    fn is_allowed(&self, op: NonPrimitiveOpType) -> bool {
        self.allowed.contains(&op)
    }
}
