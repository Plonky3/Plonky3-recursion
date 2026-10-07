// Share fixture types so their generic proof code is compiled once per suite.
#[path = "../common/mod.rs"]
mod common;

#[path = "../aggregation_profile.rs"]
mod aggregation_profile;
#[path = "../artifact_import.rs"]
mod artifact_import;
#[path = "../artifact_recursive_roundtrip.rs"]
mod artifact_recursive_roundtrip;
#[path = "../artifact_roundtrip.rs"]
mod artifact_roundtrip;
#[path = "../prepared_aggregation.rs"]
mod prepared_aggregation;
#[path = "../prepared_input_contract.rs"]
mod prepared_input_contract;
#[path = "../prepared_layer.rs"]
mod prepared_layer;
#[path = "../profile_fixed_point.rs"]
mod profile_fixed_point;
#[path = "../profile_flag_byte_identical.rs"]
mod profile_flag_byte_identical;
#[path = "../profile_tamper.rs"]
mod profile_tamper;
