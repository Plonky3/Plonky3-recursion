//! Compact, lazy STARK opening-layout metadata.
//!
//! This module deliberately contains no commitments, proof values, targets, or
//! AIR relation identity.  It describes only the validated statement routing
//! needed by native transcript replay and recursive PCS assembly.

use thiserror::Error;

/// The commitment roles emitted by the STARK transcript.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommitmentRole {
    Random,
    Trace,
    Quotient,
    Preprocessed,
    Permutation,
}

/// Matrix provenance within one commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MatrixRoute {
    Random { instance: usize },
    Trace { instance: usize },
    Quotient { instance: usize, chunk: usize },
    Preprocessed { instance: usize, matrix: usize },
    Permutation { instance: usize },
}

/// One lazily materialized matrix's opening geometry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MatrixOpeningLayout {
    pub(crate) route: MatrixRoute,
    /// PCS matrix domain height, not the extended LDE/MMCS height.
    pub(crate) log_height: usize,
    /// Base-column width before any hiding-FRI tail is merged.
    pub(crate) width: usize,
    pub(crate) point_count: usize,
    /// Base trace-domain log used to compute a next-row opening, if any.
    pub(crate) next_step_log: Option<usize>,
}

/// Per-instance dimensions used by all STARK commitment routes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct InstanceLayout {
    /// Number of base-field columns in one extension-field opening.
    pub(crate) challenge_width: usize,
    pub(crate) ext_log: usize,
    pub(crate) base_log: usize,
    pub(crate) trace_width: usize,
    pub(crate) trace_next: bool,
    pub(crate) pre_width: usize,
    pub(crate) pre_next: bool,
    pub(crate) quotient_log: usize,
    pub(crate) quotient_chunks: usize,
    pub(crate) permutation_width: usize,
}

/// Integer-layout validation failures.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub(crate) enum LayoutError {
    #[error("STARK quotient chunk count overflows for log degree {log_degree}")]
    QuotientCountOverflow { log_degree: usize },
    #[error("STARK quotient matrix count overflows")]
    QuotientMatrixCountOverflow,
    #[error("preprocessed matrix route index {index} is out of bounds")]
    PreprocessedIndexOutOfBounds { index: usize },
    #[error("preprocessed matrix route repeats instance {index}")]
    DuplicatePreprocessedIndex { index: usize },
    #[error("preprocessed matrix route points to zero-width instance {index}")]
    PreprocessedWidthZero { index: usize },
}

/// Computes `2^log_degree` without allowing a shift panic.
pub(crate) fn checked_power_of_two(log_degree: usize) -> Result<usize, LayoutError> {
    let shift =
        u32::try_from(log_degree).map_err(|_| LayoutError::QuotientCountOverflow { log_degree })?;
    1usize
        .checked_shl(shift)
        .ok_or(LayoutError::QuotientCountOverflow { log_degree })
}

/// Computes the total number of quotient matrices without allocating a chunk list.
pub(crate) fn checked_quotient_matrix_count(
    instances: &[InstanceLayout],
) -> Result<usize, LayoutError> {
    instances.iter().try_fold(0usize, |total, instance| {
        total
            .checked_add(instance.quotient_chunks)
            .ok_or(LayoutError::QuotientMatrixCountOverflow)
    })
}

/// The shared integer opening layout.
pub(crate) struct NativeStarkLayout<'a> {
    pub(crate) instances: alloc::vec::Vec<InstanceLayout>,
    pub(crate) preprocessed_order: &'a [usize],
    pub(crate) has_random: bool,
    pub(crate) has_preprocessed: bool,
    pub(crate) has_permutation: bool,
}

impl<'a> NativeStarkLayout<'a> {
    pub(crate) fn new(
        instances: alloc::vec::Vec<InstanceLayout>,
        preprocessed_order: &'a [usize],
        has_random: bool,
        has_preprocessed: bool,
        has_permutation: bool,
    ) -> Result<Self, LayoutError> {
        for (position, &index) in preprocessed_order.iter().enumerate() {
            if index >= instances.len() {
                return Err(LayoutError::PreprocessedIndexOutOfBounds { index });
            }
            if instances[index].pre_width == 0 {
                return Err(LayoutError::PreprocessedWidthZero { index });
            }
            if preprocessed_order[..position].contains(&index) {
                return Err(LayoutError::DuplicatePreprocessedIndex { index });
            }
        }
        for instance in &instances {
            let quotient_log = instance.ext_log.checked_add(instance.quotient_log).ok_or(
                LayoutError::QuotientCountOverflow {
                    log_degree: instance.ext_log,
                },
            )?;
            checked_power_of_two(quotient_log)?;
        }
        checked_quotient_matrix_count(&instances)?;
        Ok(Self {
            instances,
            preprocessed_order,
            has_random,
            has_preprocessed,
            has_permutation,
        })
    }

    pub(crate) fn commitment_count(&self) -> usize {
        usize::from(self.has_random)
            + 2 // trace and quotient
            + usize::from(self.has_preprocessed)
            + usize::from(self.has_permutation)
    }

    pub(crate) const fn commitment_role(&self, ordinal: usize) -> Option<CommitmentRole> {
        let mut next = 0;
        if self.has_random {
            if ordinal == next {
                return Some(CommitmentRole::Random);
            }
            next += 1;
        }
        if ordinal == next {
            return Some(CommitmentRole::Trace);
        }
        next += 1;
        if ordinal == next {
            return Some(CommitmentRole::Quotient);
        }
        next += 1;
        if self.has_preprocessed {
            if ordinal == next {
                return Some(CommitmentRole::Preprocessed);
            }
            next += 1;
        }
        if self.has_permutation && ordinal == next {
            return Some(CommitmentRole::Permutation);
        }
        None
    }

    pub(crate) const fn matrices(&self, role: CommitmentRole) -> MatrixLayoutIter<'_> {
        MatrixLayoutIter {
            layout: self,
            role,
            instance: 0,
            chunk: 0,
            preprocessed: 0,
        }
    }
}

pub(crate) struct MatrixLayoutIter<'a> {
    layout: &'a NativeStarkLayout<'a>,
    role: CommitmentRole,
    instance: usize,
    chunk: usize,
    preprocessed: usize,
}

impl Iterator for MatrixLayoutIter<'_> {
    type Item = MatrixOpeningLayout;

    fn next(&mut self) -> Option<Self::Item> {
        if (self.role == CommitmentRole::Random && !self.layout.has_random)
            || (self.role == CommitmentRole::Preprocessed && !self.layout.has_preprocessed)
            || (self.role == CommitmentRole::Permutation && !self.layout.has_permutation)
        {
            return None;
        }
        match self.role {
            CommitmentRole::Random => {
                let instance = self.instance;
                let info = self.layout.instances.get(instance)?;
                self.instance += 1;
                Some(MatrixOpeningLayout {
                    route: MatrixRoute::Random { instance },
                    log_height: info.ext_log,
                    width: info.challenge_width,
                    point_count: 1,
                    next_step_log: None,
                })
            }
            CommitmentRole::Trace => {
                let instance = self.instance;
                let info = self.layout.instances.get(instance)?;
                self.instance += 1;
                Some(MatrixOpeningLayout {
                    route: MatrixRoute::Trace { instance },
                    log_height: info.ext_log,
                    width: info.trace_width,
                    point_count: usize::from(info.trace_next) + 1,
                    next_step_log: info.trace_next.then_some(info.base_log),
                })
            }
            CommitmentRole::Quotient => loop {
                let info = self.layout.instances.get(self.instance)?;
                if self.chunk == info.quotient_chunks {
                    self.instance += 1;
                    self.chunk = 0;
                    continue;
                }
                let chunk = self.chunk;
                self.chunk += 1;
                return Some(MatrixOpeningLayout {
                    route: MatrixRoute::Quotient {
                        instance: self.instance,
                        chunk,
                    },
                    log_height: info.ext_log,
                    width: info.challenge_width,
                    point_count: 1,
                    next_step_log: None,
                });
            },
            CommitmentRole::Preprocessed => {
                let matrix = self.preprocessed;
                let &instance = self.layout.preprocessed_order.get(matrix)?;
                self.preprocessed += 1;
                let info = self.layout.instances[instance];
                Some(MatrixOpeningLayout {
                    route: MatrixRoute::Preprocessed { instance, matrix },
                    log_height: info.ext_log,
                    width: info.pre_width,
                    point_count: usize::from(info.pre_next) + 1,
                    next_step_log: info.pre_next.then_some(info.base_log),
                })
            }
            CommitmentRole::Permutation => loop {
                let info = self.layout.instances.get(self.instance)?;
                let instance = self.instance;
                self.instance += 1;
                if info.permutation_width == 0 {
                    continue;
                }
                return Some(MatrixOpeningLayout {
                    route: MatrixRoute::Permutation { instance },
                    log_height: info.ext_log,
                    width: info.permutation_width,
                    point_count: 2,
                    next_step_log: Some(info.base_log),
                });
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instance(quotient_chunks: usize) -> InstanceLayout {
        InstanceLayout {
            ext_log: 8,
            base_log: 7,
            challenge_width: 4,
            trace_width: 3,
            trace_next: true,
            pre_width: 2,
            pre_next: true,
            quotient_log: 1,
            quotient_chunks,
            permutation_width: 1,
        }
    }

    #[test]
    fn routes_are_lazy_and_matrix_major() {
        let map = [1, 0];
        let layout = NativeStarkLayout::new(
            alloc::vec![instance(2), instance(1)],
            &map,
            true,
            true,
            true,
        )
        .unwrap();
        assert_eq!(layout.commitment_count(), 5);
        assert_eq!(layout.commitment_role(0), Some(CommitmentRole::Random));
        assert_eq!(layout.commitment_role(1), Some(CommitmentRole::Trace));
        let pre: alloc::vec::Vec<_> = layout.matrices(CommitmentRole::Preprocessed).collect();
        assert_eq!(
            pre[0].route,
            MatrixRoute::Preprocessed {
                instance: 1,
                matrix: 0
            }
        );
        assert_eq!(
            pre[1].route,
            MatrixRoute::Preprocessed {
                instance: 0,
                matrix: 1
            }
        );
        assert_eq!(pre[0].point_count, 2);
        assert_eq!(pre[0].log_height, 8);
        let random: alloc::vec::Vec<_> = layout.matrices(CommitmentRole::Random).collect();
        assert_eq!(random[0].width, 4);
        let quotient: alloc::vec::Vec<_> = layout.matrices(CommitmentRole::Quotient).collect();
        assert_eq!(quotient.len(), 3);
        assert_eq!(quotient[0].log_height, 8);
        let permutation: alloc::vec::Vec<_> =
            layout.matrices(CommitmentRole::Permutation).collect();
        assert_eq!(permutation[0].point_count, 2);
        assert_eq!(permutation[0].next_step_log, Some(7));
    }

    #[test]
    fn routes_preserve_single_point_accesses_and_sparse_maps() {
        let mut first = instance(0);
        first.trace_next = false;
        first.pre_next = false;
        first.permutation_width = 0;
        let mut second = instance(1);
        second.trace_next = false;
        second.pre_width = 0;
        second.pre_next = false;
        let result = NativeStarkLayout::new(alloc::vec![first, second], &[1], false, true, true);
        assert!(matches!(
            result,
            Err(LayoutError::PreprocessedWidthZero { index: 1 })
        ));

        second.pre_width = 2;
        let layout =
            NativeStarkLayout::new(alloc::vec![first, second], &[1], false, true, true).unwrap();

        let trace: alloc::vec::Vec<_> = layout.matrices(CommitmentRole::Trace).collect();
        assert_eq!(trace[0].point_count, 1);
        assert_eq!(trace[1].point_count, 1);
        let pre: alloc::vec::Vec<_> = layout.matrices(CommitmentRole::Preprocessed).collect();
        assert_eq!(pre.len(), 1);
        assert_eq!(pre[0].point_count, 1);
        assert_eq!(
            pre[0].route,
            MatrixRoute::Preprocessed {
                instance: 1,
                matrix: 0
            }
        );
        let permutation: alloc::vec::Vec<_> =
            layout.matrices(CommitmentRole::Permutation).collect();
        assert_eq!(permutation.len(), 1);
        assert_eq!(
            permutation[0].route,
            MatrixRoute::Permutation { instance: 1 }
        );
        assert_eq!(permutation[0].point_count, 2);

        // An increasing sparse map must not synthesize an opening for the
        // omitted middle instance.
        let mut third = instance(1);
        third.pre_width = 3;
        third.pre_next = false;
        let sparse = NativeStarkLayout::new(
            alloc::vec![
                first,
                InstanceLayout {
                    pre_width: 0,
                    ..second
                },
                third
            ],
            &[0, 2],
            false,
            true,
            false,
        )
        .unwrap();
        let sparse_pre: alloc::vec::Vec<_> =
            sparse.matrices(CommitmentRole::Preprocessed).collect();
        assert_eq!(
            sparse_pre
                .iter()
                .map(|opening| opening.route)
                .collect::<alloc::vec::Vec<_>>(),
            alloc::vec![
                MatrixRoute::Preprocessed {
                    instance: 0,
                    matrix: 0
                },
                MatrixRoute::Preprocessed {
                    instance: 2,
                    matrix: 1
                }
            ]
        );
        assert_eq!(sparse_pre[0].point_count, 1);
        assert_eq!(sparse_pre[1].point_count, 1);
    }

    #[test]
    fn rejects_route_overflow_and_bad_maps() {
        assert!(matches!(
            checked_power_of_two(usize::BITS as usize),
            Err(LayoutError::QuotientCountOverflow { .. })
        ));
        if usize::BITS > 32 {
            let too_large = usize::try_from(u64::from(u32::MAX) + 1).unwrap();
            assert!(matches!(
                checked_power_of_two(too_large),
                Err(LayoutError::QuotientCountOverflow { .. })
            ));
        }
        let instances = alloc::vec![instance(1)];
        assert!(matches!(
            NativeStarkLayout::new(instances.clone(), &[1], false, true, false),
            Err(LayoutError::PreprocessedIndexOutOfBounds { .. })
        ));
        assert!(matches!(
            NativeStarkLayout::new(instances, &[0, 0], false, true, false),
            Err(LayoutError::DuplicatePreprocessedIndex { .. })
        ));
    }
}
