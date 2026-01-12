use clap::ArgMatches;
use clap_utils::{parse_optional, parse_required};
use environment::Environment;
use eth2::{BeaconNodeHttpClient, SensitiveUrl, Timeouts, types::BlockId};
use eth2_network_config::Eth2NetworkConfig;
use execution_layer::NewPayloadRequest;
use serde_json::json;
use ssz::Encode;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;
use tracing::{error, info};
use tree_hash::TreeHash;
use types::{EthSpec, ForkName};

const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

pub fn run<E: EthSpec>(
    env: Environment<E>,
    network_config: Eth2NetworkConfig,
    matches: &ArgMatches,
) -> Result<(), String> {
    let executor = env.core_context().executor;

    executor
        .handle()
        .ok_or("shutdown in progress")?
        .block_on(async move { run_async::<E>(network_config, matches).await })
}

async fn run_async<E: EthSpec>(
    network_config: Eth2NetworkConfig,
    matches: &ArgMatches,
) -> Result<(), String> {
    let spec = network_config
        .chain_spec::<E>()
        .map_err(|e| format!("Failed to load chain spec: {}", e))?;

    // Parse arguments
    let slot: u64 = parse_required(matches, "slot")?;
    let beacon_url: Option<String> = parse_optional(matches, "beacon-url")?;
    let output_path: Option<PathBuf> = parse_optional(matches, "output")?;

    // Default to localhost if no URL provided
    let beacon_url_str = beacon_url.unwrap_or_else(|| "http://localhost:5052".to_string());
    let beacon_url = SensitiveUrl::parse(&beacon_url_str)
        .map_err(|e| format!("Invalid beacon URL '{}': {}", beacon_url_str, e))?;

    info!("Fetching block at slot {} from {}", slot, beacon_url);

    // Initialize HTTP client
    let client = BeaconNodeHttpClient::new(beacon_url, Timeouts::set_all(HTTP_TIMEOUT));

    // Fetch beacon block
    let block_id = BlockId::Slot(slot.into());
    let response = client
        .get_beacon_blocks::<E>(block_id)
        .await
        .map_err(|e| format!("Failed to fetch block: {}", e))?;

    let beacon_response = response.ok_or_else(|| format!("Block at slot {} not found", slot))?;

    let signed_block = beacon_response.data().clone();

    info!(
        "Successfully fetched block at slot {} (block root: 0x{})",
        signed_block.message().slot(),
        hex::encode(signed_block.canonical_root())
    );

    // Get fork name for the block
    let fork_name = signed_block.message().fork_name(&spec).map_err(|_e| {
        format!("Failed to determine fork name: block variant inconsistent with slot")
    })?;

    // Check if this is a post-merge block
    if fork_name == ForkName::Base || fork_name == ForkName::Altair {
        return Err(format!(
            "Block at slot {} is a pre-merge {} block and does not have an execution payload",
            slot, fork_name
        ));
    }

    info!("Block fork: {}", fork_name);

    // Convert to NewPayloadRequest
    let new_payload_request: NewPayloadRequest<E> = signed_block
        .message()
        .try_into()
        .map_err(|e| format!("Failed to convert block to NewPayloadRequest: {:?}", e))?;

    // Perform validation
    info!("Validating payload integrity...");

    let mut validation_results = json!({
        "block_hash_valid": false,
        "versioned_hashes_valid": false,
        "optimistic_sync_verifications_passed": false,
    });

    // Verify block hash
    if let Err(e) = new_payload_request.verify_payload_block_hash() {
        error!("Block hash validation failed: {:?}", e);
        return Err(format!("Block hash validation failed: {:?}", e));
    } else {
        validation_results["block_hash_valid"] = json!(true);
        info!("Block hash validation: PASSED");
    }

    // Verify versioned hashes (only for Deneb+)
    match fork_name {
        ForkName::Deneb | ForkName::Electra | ForkName::Fulu | ForkName::Gloas => {
            if let Err(e) = new_payload_request.verify_versioned_hashes() {
                error!("Versioned hashes validation failed: {:?}", e);
                return Err(format!("Versioned hashes validation failed: {:?}", e));
            } else {
                validation_results["versioned_hashes_valid"] = json!(true);
                info!("Versioned hashes validation: PASSED");
            }
        }
        _ => {
            validation_results["versioned_hashes_valid"] = json!(null);
        }
    }

    // Perform optimistic sync verifications
    if let Err(e) = new_payload_request.perform_optimistic_sync_verifications() {
        error!("Optimistic sync verifications failed: {:?}", e);
        return Err(format!("Optimistic sync verifications failed: {:?}", e));
    } else {
        validation_results["optimistic_sync_verifications_passed"] = json!(true);
        info!("Optimistic sync verifications: PASSED");
    }

    info!("All validation checks passed");

    // Compute tree hash root of the entire NewPayloadRequest
    let tree_hash_root = compute_new_payload_request_tree_hash(&new_payload_request);
    info!(
        "NewPayloadRequest tree hash root: 0x{}",
        hex::encode(tree_hash_root)
    );

    // Build JSON output
    let output_json = build_json_output(
        &new_payload_request,
        fork_name,
        validation_results,
        tree_hash_root,
    )?;

    // Pretty print JSON
    let json_string = serde_json::to_string_pretty(&output_json)
        .map_err(|e| format!("Failed to serialize JSON: {}", e))?;

    // Output to file or stdout
    if let Some(output_path) = output_path {
        let mut file = File::create(&output_path)
            .map_err(|e| format!("Failed to create output file: {}", e))?;
        file.write_all(json_string.as_bytes())
            .map_err(|e| format!("Failed to write to output file: {}", e))?;
        info!("Output written to {}", output_path.display());
    } else {
        println!("{}", json_string);
    }

    Ok(())
}

fn build_json_output<E: EthSpec>(
    request: &NewPayloadRequest<E>,
    fork_name: ForkName,
    validation: serde_json::Value,
    tree_hash_root: tree_hash::Hash256,
) -> Result<serde_json::Value, String> {
    let payload_ref = request.execution_payload_ref();

    // Base payload fields (common to all forks)
    let mut payload_json = json!({
        "parent_hash": format!("0x{}", payload_ref.parent_hash()),
        "fee_recipient": format!("0x{}", hex::encode(payload_ref.fee_recipient())),
        "state_root": format!("0x{}", hex::encode(payload_ref.state_root())),
        "receipts_root": format!("0x{}", hex::encode(payload_ref.receipts_root())),
        "logs_bloom": format!("0x{}", hex::encode(&**payload_ref.logs_bloom())),
        "prev_randao": format!("0x{}", hex::encode(payload_ref.prev_randao())),
        "block_number": payload_ref.block_number(),
        "gas_limit": payload_ref.gas_limit(),
        "gas_used": payload_ref.gas_used(),
        "timestamp": payload_ref.timestamp(),
        "extra_data": format!("0x{}", hex::encode(&**payload_ref.extra_data())),
        "base_fee_per_gas": format!("{}", payload_ref.base_fee_per_gas()),
        "block_hash": format!("0x{}", payload_ref.block_hash()),
        "transactions": payload_ref
            .transactions()
            .iter()
            .map(|tx| format!("0x{}", hex::encode(&**tx)))
            .collect::<Vec<_>>(),
    });

    // Add Capella+ fields
    if matches!(
        fork_name,
        ForkName::Capella | ForkName::Deneb | ForkName::Electra | ForkName::Fulu | ForkName::Gloas
    ) {
        if let Ok(withdrawals) = payload_ref.withdrawals() {
            payload_json["withdrawals"] = json!(
                withdrawals
                    .iter()
                    .map(|w| {
                        json!({
                            "index": w.index,
                            "validator_index": w.validator_index,
                            "address": format!("0x{}", hex::encode(w.address)),
                            "amount": w.amount,
                        })
                    })
                    .collect::<Vec<_>>()
            );
        }
    }

    // Add Deneb+ fields
    if matches!(
        fork_name,
        ForkName::Deneb | ForkName::Electra | ForkName::Fulu | ForkName::Gloas
    ) {
        if let Ok(blob_gas_used) = payload_ref.blob_gas_used() {
            payload_json["blob_gas_used"] = json!(blob_gas_used);
        }
        if let Ok(excess_blob_gas) = payload_ref.excess_blob_gas() {
            payload_json["excess_blob_gas"] = json!(excess_blob_gas);
        }
    }

    // Build the complete output
    let mut output = json!({
        "fork": fork_name.to_string(),
        "tree_hash_root": format!("0x{}", hex::encode(tree_hash_root)),
        "validation": validation,
        "execution_payload": payload_json,
    });

    // Add versioned hashes for Deneb+
    match request {
        NewPayloadRequest::Deneb(req) => {
            output["versioned_hashes"] = json!(
                req.versioned_hashes
                    .iter()
                    .map(|vh| format!("0x{}", hex::encode(vh)))
                    .collect::<Vec<_>>()
            );
            output["parent_beacon_block_root"] =
                json!(format!("0x{}", hex::encode(req.parent_beacon_block_root)));
        }
        NewPayloadRequest::Electra(req) => {
            output["versioned_hashes"] = json!(
                req.versioned_hashes
                    .iter()
                    .map(|vh| format!("0x{}", hex::encode(vh)))
                    .collect::<Vec<_>>()
            );
            output["parent_beacon_block_root"] =
                json!(format!("0x{}", hex::encode(req.parent_beacon_block_root)));
            output["execution_requests"] = json!(format!(
                "0x{}",
                hex::encode(req.execution_requests.as_ssz_bytes())
            ));
        }
        NewPayloadRequest::Fulu(req) => {
            output["versioned_hashes"] = json!(
                req.versioned_hashes
                    .iter()
                    .map(|vh| format!("0x{}", hex::encode(vh)))
                    .collect::<Vec<_>>()
            );
            output["parent_beacon_block_root"] =
                json!(format!("0x{}", hex::encode(req.parent_beacon_block_root)));
            output["execution_requests"] = json!(format!(
                "0x{}",
                hex::encode(req.execution_requests.as_ssz_bytes())
            ));
        }
        NewPayloadRequest::Gloas(req) => {
            output["versioned_hashes"] = json!(
                req.versioned_hashes
                    .iter()
                    .map(|vh| format!("0x{}", hex::encode(vh)))
                    .collect::<Vec<_>>()
            );
            output["parent_beacon_block_root"] =
                json!(format!("0x{}", hex::encode(req.parent_beacon_block_root)));
            output["execution_requests"] = json!(format!(
                "0x{}",
                hex::encode(req.execution_requests.as_ssz_bytes())
            ));
        }
        _ => {}
    }

    Ok(output)
}

/// Computes the tree hash root of the entire NewPayloadRequest structure.
/// This includes the execution payload, versioned hashes, parent beacon block root,
/// and execution requests (depending on the fork).
fn compute_new_payload_request_tree_hash<E: EthSpec>(
    request: &NewPayloadRequest<E>,
) -> tree_hash::Hash256 {
    use tree_hash::MerkleHasher;

    match request {
        NewPayloadRequest::Bellatrix(req) => {
            // For Bellatrix/Capella, only hash the execution payload
            let payload = req.execution_payload.clone();
            payload.tree_hash_root()
        }
        NewPayloadRequest::Capella(req) => {
            let payload = req.execution_payload.clone();
            payload.tree_hash_root()
        }
        NewPayloadRequest::Deneb(req) => {
            // For Deneb+, hash execution payload + versioned hashes + parent beacon block root
            let mut hasher = MerkleHasher::with_leaves(3);

            // Hash execution payload
            let payload = req.execution_payload.clone();
            hasher
                .write(payload.tree_hash_root().as_ref())
                .expect("should write execution payload hash");

            // Hash versioned hashes (as a list) - compute tree hash of the vector
            let versioned_hashes_root = tree_hash_list(&req.versioned_hashes);
            hasher
                .write(versioned_hashes_root.as_ref())
                .expect("should write versioned hashes");

            // Hash parent beacon block root
            hasher
                .write(req.parent_beacon_block_root.as_ref())
                .expect("should write parent beacon block root");

            tree_hash::Hash256::from_slice(hasher.finish().expect("should finish hashing").as_ref())
        }
        NewPayloadRequest::Electra(req) => {
            // For Electra+, hash execution payload + versioned hashes + parent beacon block root + execution requests
            let mut hasher = MerkleHasher::with_leaves(4);

            // Hash execution payload
            let payload = req.execution_payload.clone();
            hasher
                .write(payload.tree_hash_root().as_ref())
                .expect("should write execution payload hash");
            info!("hellooo {}", hex::encode(payload.tree_hash_root()));

            // Hash versioned hashes
            let versioned_hashes_root = tree_hash_list(&req.versioned_hashes);
            hasher
                .write(versioned_hashes_root.as_ref())
                .expect("should write versioned hashes");

            // Hash parent beacon block root
            hasher
                .write(req.parent_beacon_block_root.as_ref())
                .expect("should write parent beacon block root");

            // Hash execution requests
            hasher
                .write(req.execution_requests.tree_hash_root().as_ref())
                .expect("should write execution requests");

            tree_hash::Hash256::from_slice(hasher.finish().expect("should finish hashing").as_ref())
        }
        NewPayloadRequest::Fulu(req) => {
            let mut hasher = MerkleHasher::with_leaves(4);

            let payload = req.execution_payload.clone();
            hasher
                .write(payload.tree_hash_root().as_ref())
                .expect("should write execution payload hash");

            let versioned_hashes_root = tree_hash_list(&req.versioned_hashes);
            hasher
                .write(versioned_hashes_root.as_ref())
                .expect("should write versioned hashes");

            hasher
                .write(req.parent_beacon_block_root.as_ref())
                .expect("should write parent beacon block root");

            hasher
                .write(req.execution_requests.tree_hash_root().as_ref())
                .expect("should write execution requests");

            tree_hash::Hash256::from_slice(hasher.finish().expect("should finish hashing").as_ref())
        }
        NewPayloadRequest::Gloas(req) => {
            let mut hasher = MerkleHasher::with_leaves(4);

            let payload = req.execution_payload.clone();
            hasher
                .write(payload.tree_hash_root().as_ref())
                .expect("should write execution payload hash");

            let versioned_hashes_root = tree_hash_list(&req.versioned_hashes);
            hasher
                .write(versioned_hashes_root.as_ref())
                .expect("should write versioned hashes");

            hasher
                .write(req.parent_beacon_block_root.as_ref())
                .expect("should write parent beacon block root");

            hasher
                .write(req.execution_requests.tree_hash_root().as_ref())
                .expect("should write execution requests");

            tree_hash::Hash256::from_slice(hasher.finish().expect("should finish hashing").as_ref())
        }
    }
}

/// Helper function to compute tree hash root of a list of Hash256 values (versioned hashes)
fn tree_hash_list(list: &[types::Hash256]) -> tree_hash::Hash256 {
    use tree_hash::MerkleHasher;

    if list.is_empty() {
        return tree_hash::Hash256::from([0u8; 32]);
    }

    // For a list of fixed-size elements (Hash256), we hash them as a packed structure
    let mut hasher = MerkleHasher::with_leaves(list.len());

    for hash in list {
        hasher.write(hash.as_ref()).expect("should write hash");
    }

    tree_hash::Hash256::from_slice(hasher.finish().expect("should finish hashing").as_ref())
}
