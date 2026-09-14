//! Per-thread probes for WHIR acceptance-order unit tests.

use std::cell::RefCell;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Counters {
    pub(crate) target_new: usize,
    pub(crate) get_values: usize,
    pub(crate) get_private_values: usize,
    pub(crate) target_challenger: usize,
    pub(crate) transcript_replay: usize,
    pub(crate) query_replay: usize,
    pub(crate) restoration: usize,
}

std::thread_local! {
    static ACTIVE: RefCell<Option<Counters>> = const { RefCell::new(None) };
}

fn mark(update: impl FnOnce(&mut Counters)) {
    ACTIVE.with(|active| {
        if let Some(counters) = active.borrow_mut().as_mut() {
            update(counters);
        }
    });
}

pub(crate) fn measure<R>(f: impl FnOnce() -> R) -> (R, Counters) {
    ACTIVE.with(|active| {
        assert!(
            active.replace(Some(Counters::default())).is_none(),
            "WHIR acceptance probes cannot be nested"
        );
    });
    let result = f();
    let counters = ACTIVE.with(|active| {
        active
            .borrow_mut()
            .take()
            .expect("WHIR acceptance probe remained active")
    });
    (result, counters)
}

pub(crate) fn target_new() {
    mark(|counters| counters.target_new += 1);
}

pub(crate) fn get_values() {
    mark(|counters| counters.get_values += 1);
}

pub(crate) fn get_private_values() {
    mark(|counters| counters.get_private_values += 1);
}

pub(crate) fn target_challenger() {
    mark(|counters| counters.target_challenger += 1);
}

pub(crate) fn transcript_replay() {
    mark(|counters| counters.transcript_replay += 1);
}

pub(crate) fn query_replay() {
    mark(|counters| counters.query_replay += 1);
}

pub(crate) fn restoration() {
    mark(|counters| counters.restoration += 1);
}
