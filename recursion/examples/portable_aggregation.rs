//! Four-leaf state-transition aggregation across fresh processes.
//!
//! The FRI query counts and trace packing below are intentionally small teaching/test settings.
//! Do not use them as security parameters.

use std::boxed::Box;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use p3_circuit::{Circuit, CircuitBuilder, StateTransitionLayout, StatementExport};
use p3_circuit_prover::common::{NpoAirBuilder, NpoPreprocessor};
use p3_circuit_prover::{
    BatchStarkProof, BatchStarkProver, ConstraintProfile, PreparedCircuitProver,
    StatementAirBuilder, StatementPreprocessor, StatementProver, TablePacking,
};
use p3_field::extension::BinomialExtensionField;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_koala_bear::KoalaBear;
use p3_recursion::artifact::{
    ArtifactLimits, CanonicalStatement, ExpectedVerifierArtifact, PortableArtifactExport,
    PortableArtifactImport, PortableVerifier, TypedArtifactVerifier,
};
use p3_recursion::builtin_config::{
    FriConfigV1, KoalaBearD4Poseidon2BinaryConfig, SuiteIdV1, koala_bear_d4_poseidon2_binary,
};
use p3_recursion::{
    BatchOnly, FriRecursionBackend, FriRecursionBackendForExt, Poseidon2Config,
    ProveNextLayerParams, TrustedPreparedAggregation, TrustedPreparedInput, TrustedPreparedSource,
};

type F = KoalaBear;
type Challenge = BinomialExtensionField<F, 4>;
type Config = KoalaBearD4Poseidon2BinaryConfig;

const PRODUCED_LEAVES: [[u32; 5]; 4] = [
    [10, 20, 11, 22, 1],
    [11, 22, 13, 26, 2],
    [13, 26, 16, 32, 3],
    [16, 32, 20, 40, 4],
];

// Trusted setup uses a different, valid witness under the same circuit relation.
const SETUP_LEAVES: [[u32; 5]; 4] = [
    [30, 50, 31, 52, 1],
    [31, 52, 33, 56, 2],
    [33, 56, 36, 62, 3],
    [36, 62, 40, 70, 4],
];

const fn descriptor(
    num_queries: u32,
    input_cap_height: u32,
    commit_cap_height: u32,
) -> FriConfigV1 {
    FriConfigV1::new(
        SuiteIdV1::KoalaBearD4Poseidon2BinaryFri,
        1,
        0,
        2,
        num_queries,
        0,
        0,
        input_cap_height,
        commit_cap_height,
        0,
        0,
    )
}

fn leaf_config(limits: &ArtifactLimits) -> Result<Config, String> {
    koala_bear_d4_poseidon2_binary(&descriptor(2, 1, 0), &limits.verifier)
        .map_err(|error| format!("leaf config: {error}"))
}

fn layer_config(limits: &ArtifactLimits) -> Result<Config, String> {
    koala_bear_d4_poseidon2_binary(&descriptor(1, 0, 1), &limits.verifier)
        .map_err(|error| format!("layer config: {error}"))
}

fn backend() -> FriRecursionBackendForExt<4, 16, 8, Poseidon2Config> {
    FriRecursionBackend::<16, 8, _>::new(Poseidon2Config::KOALA_BEAR_D4_W16)
        .for_extension_degree::<4>()
}

fn prepare_leaf(
    config: Config,
) -> Result<(Circuit<Challenge>, PreparedCircuitProver<Config>), String> {
    let mut builder = CircuitBuilder::<Challenge>::new();
    let slots = (0..5).map(|_| builder.public_input()).collect::<Vec<_>>();
    let one = builder.add(slots[0], slots[4]);
    let twice = builder.add(slots[4], slots[4]);
    let two = builder.add(slots[1], twice);
    builder.connect(slots[2], one);
    builder.connect(slots[3], two);
    let schema = builder
        .set_statement_exports::<F>(
            &slots
                .into_iter()
                .map(StatementExport::Base)
                .collect::<Vec<_>>(),
        )
        .map_err(|error| format!("leaf statement schema: {error}"))?;
    let circuit = builder
        .build()
        .map_err(|error| format!("leaf circuit: {error}"))?;
    let preprocessors: Vec<Box<dyn NpoPreprocessor<F>>> =
        vec![Box::new(StatementPreprocessor::new(schema.clone()))];
    let air_builders: Vec<Box<dyn NpoAirBuilder<Config, 4>>> =
        vec![Box::new(StatementAirBuilder::<4>::new(schema.clone()))];
    let mut prover = BatchStarkProver::new(config)
        .with_table_packing(TablePacking::new(4, 4).with_min_trace_height(32));
    prover.register_table_prover(Box::new(StatementProver::<4>::new(schema)));
    let prepared = prover
        .prepare_circuit::<Challenge, 4>(
            &circuit,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .map_err(|error| format!("prepare leaf: {error}"))?;
    Ok((circuit, prepared))
}

fn prove_leaf(
    circuit: &Circuit<Challenge>,
    prepared: &PreparedCircuitProver<Config>,
    values: [u32; 5],
) -> Result<BatchStarkProof<Config>, String> {
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(&values.map(|value| Challenge::from(F::from_u32(value))))
        .map_err(|error| format!("leaf inputs: {error}"))?;
    let traces = runner.run().map_err(|error| format!("run leaf: {error}"))?;
    prepared
        .prove(&traces)
        .map_err(|error| format!("prove leaf: {error}"))
}

fn statement_bytes(values: &[u32; 5]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect()
}

fn output_must_be_new(path: &Path) -> Result<(), String> {
    if path.exists() {
        Err(format!("output already exists: {}", path.display()))
    } else {
        Ok(())
    }
}

fn publish_dir(path: &Path, files: &[(&str, &[u8])]) -> Result<(), String> {
    fs::create_dir(path).map_err(|error| format!("create {}: {error}", path.display()))?;
    for (name, bytes) in files {
        let file_path = path.join(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&file_path)
            .map_err(|error| format!("create {}: {error}", file_path.display()))?;
        file.write_all(bytes)
            .map_err(|error| format!("write {}: {error}", file_path.display()))?;
    }
    Ok(())
}

fn main() {
    if let Err(error) = run_cli(&std::env::args().skip(1).collect::<Vec<_>>()) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run_cli(args: &[String]) -> Result<(), String> {
    match args {
        [command, flag, dir] if command == "setup" && flag == "--trusted-dir" =>
            setup(Path::new(dir)),
        [command, flag, dir] if command == "produce" && flag == "--out-dir" =>
            produce(Path::new(dir)),
        [command, trusted_flag, trusted, children_flag, children, output_flag, output]
            if command == "aggregate"
                && trusted_flag == "--trusted-dir"
                && children_flag == "--children-dir"
                && output_flag == "--out-dir" =>
        {
            aggregate(Path::new(trusted), Path::new(children), Path::new(output))
        }
        [command, trusted_flag, trusted, root_flag, root, expected_flag, expected]
            if command == "verify"
                && trusted_flag == "--trusted-dir"
                && root_flag == "--root-dir"
                && expected_flag == "--expected" =>
        {
            verify(Path::new(trusted), Path::new(root), parse_expected(expected)?)
        }
        _ => Err("teaching/test parameters only; not for production security\nusage: setup --trusted-dir AUTH | produce --out-dir CHILDREN | aggregate --trusted-dir AUTH --children-dir CHILDREN --out-dir ROOT | verify --trusted-dir AUTH --root-dir ROOT --expected a,b,c,d,n".into()),
    }
}

fn parse_expected(text: &str) -> Result<[u32; 5], String> {
    let fields = text.split(',').collect::<Vec<_>>();
    if fields.len() != 5 {
        return Err(
            "expected statement needs exactly five comma-separated base-field values".into(),
        );
    }
    let parsed = fields
        .into_iter()
        .map(|field| {
            if field.is_empty() || !field.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(format!("invalid expected statement value: {field:?}"));
            }
            let value = field
                .parse::<u32>()
                .map_err(|error| format!("invalid value {field:?}: {error}"))?;
            if u64::from(value) >= F::ORDER_U64 {
                return Err(format!("noncanonical KoalaBear value: {value}"));
            }
            Ok(value)
        })
        .collect::<Result<Vec<_>, _>>()?;
    parsed
        .try_into()
        .map_err(|_| "expected statement needs five values".into())
}

fn read_limited(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let bound = limit.checked_add(1).ok_or("artifact read limit overflow")?;
    let mut bytes = Vec::new();
    let bound = u64::try_from(bound).map_err(|_| "artifact read limit exceeds u64")?;
    file.take(bound)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    if bytes.len() > limit {
        return Err(format!(
            "artifact exceeds {limit} bytes: {}",
            path.display()
        ));
    }
    Ok(bytes)
}

fn setup(trusted_dir: &Path) -> Result<(), String> {
    output_must_be_new(trusted_dir)?;
    let limits = ArtifactLimits::default();
    let (circuit, prepared) = prepare_leaf(leaf_config(&limits)?)?;
    let leaf_verifier = prepared.verifier();
    let leaf_bytes = leaf_verifier
        .encode_verifier_artifact(limits)
        .map_err(|error| format!("encode leaf verifier: {error}"))?;
    let proofs = SETUP_LEAVES
        .map(|values| prove_leaf(&circuit, &prepared, values))
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let statements = SETUP_LEAVES.map(|values| values.map(F::from_u32));
    let layout = StateTransitionLayout::base(2, 4).map_err(|error| error.to_string())?;
    let first_owner = TrustedPreparedAggregation::<Config, Config, BatchOnly, BatchOnly, _, 4>::new_state_transition(
        TrustedPreparedSource::BatchStark { verifier: leaf_verifier.clone(), proof: &proofs[0], statement: &statements[0] },
        TrustedPreparedSource::BatchStark { verifier: leaf_verifier, proof: &proofs[1], statement: &statements[1] },
        layer_config(&limits)?, backend(), ProveNextLayerParams::default(), layout.clone(),
    ).map_err(|error| format!("prepare first layer: {error}"))?;
    let left = first_owner
        .prove(
            TrustedPreparedInput::BatchStark {
                proof: &proofs[0],
                statement: &statements[0],
            },
            TrustedPreparedInput::BatchStark {
                proof: &proofs[1],
                statement: &statements[1],
            },
        )
        .map_err(|error| format!("prove setup left pair: {error}"))?;
    let right = first_owner
        .prove(
            TrustedPreparedInput::BatchStark {
                proof: &proofs[2],
                statement: &statements[2],
            },
            TrustedPreparedInput::BatchStark {
                proof: &proofs[3],
                statement: &statements[3],
            },
        )
        .map_err(|error| format!("prove setup right pair: {error}"))?;
    let first_verifier = first_owner.verifier();
    let left_statement = [30, 50, 33, 56, 3].map(F::from_u32);
    let right_statement = [33, 56, 40, 70, 7].map(F::from_u32);
    let root_owner = TrustedPreparedAggregation::<Config, Config, BatchOnly, BatchOnly, _, 4>::new_state_transition(
        TrustedPreparedSource::BatchStark { verifier: first_verifier.clone(), proof: &left.0, statement: &left_statement },
        TrustedPreparedSource::BatchStark { verifier: first_verifier, proof: &right.0, statement: &right_statement },
        layer_config(&limits)?, backend(), ProveNextLayerParams::default(), layout,
    ).map_err(|error| format!("prepare root: {error}"))?;
    let root_bytes = root_owner
        .verifier()
        .encode_verifier_artifact(limits)
        .map_err(|error| format!("encode root verifier: {error}"))?;
    publish_dir(
        trusted_dir,
        &[
            ("leaf.verifier", &leaf_bytes),
            ("root.verifier", &root_bytes),
        ],
    )
}

fn produce(out_dir: &Path) -> Result<(), String> {
    output_must_be_new(out_dir)?;
    let limits = ArtifactLimits::default();
    let (circuit, prepared) = prepare_leaf(leaf_config(&limits)?)?;
    let verifier = prepared.verifier();
    let verifier_bytes = verifier
        .encode_verifier_artifact(limits)
        .map_err(|error| format!("encode leaf verifier: {error}"))?;
    let proofs = PRODUCED_LEAVES
        .map(|values| prove_leaf(&circuit, &prepared, values))
        .into_iter()
        .map(|proof| {
            verifier
                .encode_proof_artifact(&proof?, limits)
                .map_err(|error| format!("encode leaf proof: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    publish_dir(
        out_dir,
        &[
            ("leaf.verifier", &verifier_bytes),
            ("leaf-0.proof", &proofs[0]),
            ("leaf-1.proof", &proofs[1]),
            ("leaf-2.proof", &proofs[2]),
            ("leaf-3.proof", &proofs[3]),
        ],
    )
}

fn aggregate(trusted_dir: &Path, children_dir: &Path, out_dir: &Path) -> Result<(), String> {
    output_must_be_new(out_dir)?;
    let limits = ArtifactLimits::default();
    let leaf_pin = read_limited(
        &trusted_dir.join("leaf.verifier"),
        limits.max_verifier_bytes,
    )?;
    let root_pin = read_limited(
        &trusted_dir.join("root.verifier"),
        limits.max_verifier_bytes,
    )?;
    let candidate = read_limited(
        &children_dir.join("leaf.verifier"),
        limits.max_verifier_bytes,
    )?;
    let importer = TypedArtifactVerifier::<Config>::decode_with_config(
        leaf_config(&limits)?,
        &candidate,
        ExpectedVerifierArtifact::from_trusted_bytes(&leaf_pin),
        limits,
    )
    .map_err(|error| format!("import leaf verifier: {error}"))?;
    let children = (0..4)
        .map(|index| {
            let path = children_dir.join(format!("leaf-{index}.proof"));
            let proof = read_limited(&path, limits.max_proof_bytes)?;
            let expected = statement_bytes(&PRODUCED_LEAVES[index]);
            importer
                .import_proof(&proof, CanonicalStatement::new(&expected, 5))
                .map_err(|error| format!("import {}: {error}", path.display()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    drop(importer);
    drop(candidate);
    drop(leaf_pin);
    let layout = StateTransitionLayout::base(2, 4).map_err(|error| error.to_string())?;
    let first_owner = TrustedPreparedAggregation::<Config, Config, BatchOnly, BatchOnly, _, 4>::new_state_transition(
        children[0].as_source(), children[1].as_source(),
        layer_config(&limits)?, backend(), ProveNextLayerParams::default(), layout.clone(),
    ).map_err(|error| format!("prepare first layer: {error}"))?;
    let left = first_owner
        .prove(children[0].as_input(), children[1].as_input())
        .map_err(|error| format!("prove left pair: {error}"))?;
    let right = first_owner
        .prove(children[2].as_input(), children[3].as_input())
        .map_err(|error| format!("prove right pair: {error}"))?;
    let first_verifier = first_owner.verifier();
    let left_statement = [10, 20, 13, 26, 3].map(F::from_u32);
    let right_statement = [13, 26, 20, 40, 7].map(F::from_u32);
    let root_owner = TrustedPreparedAggregation::<Config, Config, BatchOnly, BatchOnly, _, 4>::new_state_transition(
        TrustedPreparedSource::BatchStark { verifier: first_verifier.clone(), proof: &left.0, statement: &left_statement },
        TrustedPreparedSource::BatchStark { verifier: first_verifier, proof: &right.0, statement: &right_statement },
        layer_config(&limits)?, backend(), ProveNextLayerParams::default(), layout,
    ).map_err(|error| format!("prepare root: {error}"))?;
    let root_verifier = root_owner.verifier();
    let root_verifier_bytes = root_verifier
        .encode_verifier_artifact(limits)
        .map_err(|error| format!("encode root verifier: {error}"))?;
    if root_verifier_bytes != root_pin {
        return Err(
            "prepared root verifier differs from independently provisioned root pin".into(),
        );
    }
    let root_proof = root_owner
        .prove(
            TrustedPreparedInput::BatchStark {
                proof: &left.0,
                statement: &left_statement,
            },
            TrustedPreparedInput::BatchStark {
                proof: &right.0,
                statement: &right_statement,
            },
        )
        .map_err(|error| format!("prove root: {error}"))?;
    let root_proof_bytes = root_verifier
        .encode_proof_artifact(&root_proof.0, limits)
        .map_err(|error| format!("encode root proof: {error}"))?;
    publish_dir(
        out_dir,
        &[
            ("root.verifier", &root_verifier_bytes),
            ("root.proof", &root_proof_bytes),
        ],
    )
}

fn verify(trusted_dir: &Path, root_dir: &Path, expected: [u32; 5]) -> Result<(), String> {
    let limits = ArtifactLimits::default();
    let pin = read_limited(
        &trusted_dir.join("root.verifier"),
        limits.max_verifier_bytes,
    )?;
    let candidate = read_limited(&root_dir.join("root.verifier"), limits.max_verifier_bytes)?;
    let proof = read_limited(&root_dir.join("root.proof"), limits.max_proof_bytes)?;
    let portable = PortableVerifier::decode(
        &candidate,
        ExpectedVerifierArtifact::from_trusted_bytes(&pin),
        limits,
    )
    .map_err(|error| format!("decode pinned root verifier: {error}"))?;
    let expected_bytes = statement_bytes(&expected);
    portable
        .verify_encoded(&proof, CanonicalStatement::new(&expected_bytes, 5))
        .map_err(|error| format!("verify expected root statement: {error}"))?;
    println!("verified root statement: {expected:?}");
    Ok(())
}

#[cfg(test)]
mod process_tests {
    use std::fs;
    use std::path::PathBuf;
    use std::process::{Command, Output};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    const WORKER_ARGS: &str = "P3_PORTABLE_AGGREGATION_WORKER_ARGS";
    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let root = std::env::temp_dir();
            let stamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            loop {
                let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
                let path = root.join(format!(
                    "p3-portable-aggregation-{}-{stamp}-{id}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("cannot create test directory: {error}"),
                }
            }
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn spawn_worker(args: &[&str]) -> Output {
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "process_tests::worker", "--nocapture"])
            .env(WORKER_ARGS, args.join("\x1f"))
            .output()
            .unwrap()
    }

    fn assert_success(output: &Output) {
        assert!(
            output.status.success(),
            "stdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains("portable_aggregation worker completed:"),
            "worker test did not run"
        );
    }

    #[test]
    fn worker() {
        let Ok(args) = std::env::var(WORKER_ARGS) else {
            return;
        };
        let args = args.split('\x1f').map(str::to_owned).collect::<Vec<_>>();
        run_cli(&args).unwrap();
        println!("portable_aggregation worker completed: {}", args[0]);
    }

    #[test]
    fn parses_exact_canonical_root_statement() {
        assert_eq!(
            parse_expected("10,20,20,40,10").unwrap(),
            [10, 20, 20, 40, 10]
        );
        for invalid in [
            "",
            "10,20,20,40",
            "10,20,20,40,10,0",
            "10, 20,20,40,10",
            "2130706433,20,20,40,10",
            "-1,20,20,40,10",
        ] {
            assert!(parse_expected(invalid).is_err(), "accepted {invalid:?}");
        }
        assert!(
            run_cli(&[
                "verify".into(),
                "--trusted-dir".into(),
                "auth".into(),
                "--root-dir".into(),
                "root".into()
            ])
            .is_err()
        );
    }

    #[test]
    fn bounded_read_rejects_oversized_file() {
        let temp = TempDir::new();
        let file = temp.join("artifact");
        fs::write(&file, [1, 2, 3]).unwrap();
        assert_eq!(read_limited(&file, 3).unwrap(), [1, 2, 3]);
        assert!(read_limited(&file, 2).is_err());
    }

    #[test]
    fn existing_output_directory_is_preserved() {
        let temp = TempDir::new();
        let output = temp.join("children");
        fs::create_dir(&output).unwrap();
        fs::write(output.join("user.txt"), b"keep").unwrap();
        let args = ["produce", "--out-dir", output.to_str().unwrap()].map(str::to_owned);
        assert!(run_cli(&args).is_err());
        assert_eq!(fs::read(output.join("user.txt")).unwrap(), b"keep");
    }

    #[test]
    fn four_fresh_processes_aggregate_and_verify_against_separate_pins() {
        let temp = TempDir::new();
        let auth = temp.join("authority");
        let children = temp.join("children");
        let root = temp.join("root");
        let a = auth.to_str().unwrap();
        let c = children.to_str().unwrap();
        let r = root.to_str().unwrap();

        assert_success(&spawn_worker(&["setup", "--trusted-dir", a]));
        let leaf_pin = fs::read(auth.join("leaf.verifier")).unwrap();
        let root_pin = fs::read(auth.join("root.verifier")).unwrap();
        assert_success(&spawn_worker(&["produce", "--out-dir", c]));
        assert_eq!(fs::read(children.join("leaf.verifier")).unwrap(), leaf_pin);
        assert_success(&spawn_worker(&[
            "aggregate",
            "--trusted-dir",
            a,
            "--children-dir",
            c,
            "--out-dir",
            r,
        ]));
        assert_eq!(fs::read(root.join("root.verifier")).unwrap(), root_pin);
        let root_proof = fs::read(root.join("root.proof")).unwrap();
        assert_success(&spawn_worker(&[
            "verify",
            "--trusted-dir",
            a,
            "--root-dir",
            r,
            "--expected",
            "10,20,20,40,10",
        ]));
        let rejected = spawn_worker(&[
            "verify",
            "--trusted-dir",
            a,
            "--root-dir",
            r,
            "--expected",
            "10,20,20,40,9",
        ]);
        assert!(!rejected.status.success());
        assert!(
            String::from_utf8_lossy(&rejected.stderr).contains("verify expected root statement")
        );
        let different_candidate = temp.join("different-candidate");
        fs::create_dir(&different_candidate).unwrap();
        fs::write(different_candidate.join("root.verifier"), &leaf_pin).unwrap();
        fs::write(different_candidate.join("root.proof"), &root_proof).unwrap();
        let different = spawn_worker(&[
            "verify",
            "--trusted-dir",
            a,
            "--root-dir",
            different_candidate.to_str().unwrap(),
            "--expected",
            "10,20,20,40,10",
        ]);
        assert!(!different.status.success());
        assert!(String::from_utf8_lossy(&different.stderr).contains("decode pinned root verifier"));
        let truncated_candidate = temp.join("truncated-candidate");
        fs::create_dir(&truncated_candidate).unwrap();
        fs::write(truncated_candidate.join("root.verifier"), &root_pin).unwrap();
        fs::write(
            truncated_candidate.join("root.proof"),
            &root_proof[..root_proof.len() - 1],
        )
        .unwrap();
        let truncated = spawn_worker(&[
            "verify",
            "--trusted-dir",
            a,
            "--root-dir",
            truncated_candidate.to_str().unwrap(),
            "--expected",
            "10,20,20,40,10",
        ]);
        assert!(!truncated.status.success());
        assert!(
            String::from_utf8_lossy(&truncated.stderr).contains("verify expected root statement")
        );
        assert_eq!(fs::read(auth.join("leaf.verifier")).unwrap(), leaf_pin);
        assert_eq!(fs::read(auth.join("root.verifier")).unwrap(), root_pin);
        assert_eq!(fs::read(root.join("root.proof")).unwrap(), root_proof);
    }
}
