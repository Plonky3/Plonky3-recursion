use p3_circuit::{StatementError, StatementField, StatementSchema};

#[test]
fn checked_public_constructor_rejects_zero_extension_degree_and_overflow() {
    assert_eq!(
        StatementSchema::try_new(vec![StatementField::Extension { degree: 0 }]),
        Err(StatementError::ZeroExtensionDegree)
    );
    assert_eq!(
        StatementSchema::try_new(vec![
            StatementField::Extension { degree: usize::MAX },
            StatementField::Base,
        ]),
        Err(StatementError::LengthOverflow)
    );
}

#[test]
fn checked_public_constructor_preserves_order_and_flattened_width() {
    let schema = StatementSchema::try_new(vec![
        StatementField::Base,
        StatementField::Extension { degree: 4 },
        StatementField::Base,
    ])
    .unwrap();

    assert_eq!(
        schema.fields(),
        &[
            StatementField::Base,
            StatementField::Extension { degree: 4 },
            StatementField::Base,
        ]
    );
    assert_eq!(schema.base_len(), 6);
}
