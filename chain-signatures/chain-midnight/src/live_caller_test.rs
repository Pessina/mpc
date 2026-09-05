use super::*;
use anyhow::Context as _;
use mpc_chain_integration_core::{MockStateManager, NoopChainTelemetry};
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LiveCase {
    node_url: String,
    central_address: String,
    caller_address: String,
    named_caller_address: String,
    request_id: String,
    transaction_file: PathBuf,
    proof_file: PathBuf,
    block_height: u64,
    block_hash: String,
    expect_request: bool,
}

struct CountingSource {
    live: LiveSource,
    reads: Mutex<Vec<(String, String)>>,
}

#[async_trait]
impl ChainSource for CountingSource {
    async fn finalized_head(&self) -> anyhow::Result<BlockRef> {
        self.live.finalized_head().await
    }

    async fn block_at(&self, number: u64) -> anyhow::Result<BlockRef> {
        self.live.block_at(number).await
    }

    async fn block_emissions(
        &self,
        block: &BlockRef,
        singleton: &[u8; 32],
    ) -> anyhow::Result<Option<BlockEmissions>> {
        self.live.block_emissions(block, singleton).await
    }

    async fn contract_state_tree(
        &self,
        address: &str,
        at_hash: &str,
    ) -> anyhow::Result<ContractState> {
        self.reads
            .lock()
            .unwrap()
            .push((address.to_string(), at_hash.to_string()));
        self.live.contract_state_tree(address, at_hash).await
    }
}

#[tokio::test]
#[ignore = "requires MIDNIGHT_LIVE_CASE JSON receipt from an isolated real-stack run"]
async fn finalized_caller_gate_precedes_state_lookup() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("mpc_chain_midnight=info")
        .with_test_writer()
        .try_init();
    let case: LiveCase =
        serde_json::from_slice(&std::fs::read(std::env::var("MIDNIGHT_LIVE_CASE")?)?)?;
    let config = MidnightConfig {
        node_url: case.node_url,
        central_address: crate::MidnightAddress::from_hex(&case.central_address)?,
        publisher: Default::default(),
        rpc: Default::default(),
        indexer: Default::default(),
    };
    let source = CountingSource {
        live: LiveSource::connect(&config).await?,
        reads: Mutex::default(),
    };
    let block = source.block_at(case.block_height).await?;
    assert_eq!(
        block.hash.trim_start_matches("0x"),
        case.block_hash.trim_start_matches("0x")
    );
    assert!(source.finalized_head().await?.number >= block.number);
    let batch = source
        .block_emissions(&block, config.central_address.as_bytes())
        .await?
        .context("receipt block contains no singleton candidate")?;
    assert_eq!(
        batch.candidates.len(),
        1,
        "require an isolated applied transaction"
    );
    assert_eq!(
        batch.candidates[0].calls.len(),
        1,
        "require one singleton call"
    );
    let captured = std::fs::read(case.transaction_file)?;
    let extrinsic = &batch.proof_seed.scale_body[batch.candidates[0].extrinsic_index as usize];
    assert!(
        !captured.is_empty()
            && extrinsic
                .windows(captured.len())
                .any(|window| window == captured),
        "captured transaction must occur in the applied candidate's actual block body"
    );
    let transaction: crate::emissions::DecodedTransaction =
        midnight_serialize::tagged_deserialize(&mut &captured[..])?;
    let mut notifications = Vec::new();
    for (intent, call) in transaction.calls() {
        println!(
            "LIVE_CALL intent={intent} address={} entry_point={} commitment={:?}",
            hex::encode(call.address.0 .0),
            String::from_utf8_lossy(&call.entry_point.0),
            call.communication_commitment
        );
        if call.address.0 .0 == *config.central_address.as_bytes() {
            for emission in crate::emissions::emissions_of_call(&call)? {
                if emission.kind == EmissionKind::SignBidirectional {
                    notifications.push(decode_notification(&emission.payload));
                }
            }
        }
    }
    assert_eq!(notifications.len(), 1);
    assert_eq!(hex::encode(notifications[0].request_id), case.request_id);
    let notification = unpack_notification_v1(&notifications[0])?;
    assert_eq!(
        hex::encode(notification.caller_address),
        case.named_caller_address.trim_start_matches("0x")
    );
    assert_eq!(notification.requests_path, vec![3]);
    let indexer = MidnightIndexer {
        config,
        state_manager: MockStateManager::new(),
        telemetry: NoopChainTelemetry,
    };
    let events = indexer.process_block(&source, &block).await?;
    let reads = source.reads.lock().unwrap();
    if case.expect_request {
        assert_eq!(events.len(), 1);
        let ChainEvent::SignRequest { request, .. } = &events[0] else {
            anyhow::bail!("expected SignRequest, got {:?}", events[0]);
        };
        assert_eq!(hex::encode(request.id.request_id), case.request_id);
        assert_eq!(
            reads.as_slice(),
            &[(
                case.caller_address.trim_start_matches("0x").to_string(),
                block.hash.clone()
            )]
        );
    } else {
        assert!(events.is_empty(), "unexpected events: {events:?}");
        assert!(reads.is_empty(), "unexpected caller state reads: {reads:?}");
    }
    std::fs::write(
        case.proof_file,
        serde_json::to_vec_pretty(&serde_json::json!({
            "blockNumber": block.number,
            "blockHash": &block.hash,
            "parentHash": &block.parent_hash,
            "genesisHash": hex::encode(batch.proof_seed.reported_genesis_hash),
            "singletonAddress": hex::encode(batch.proof_seed.singleton_address),
            "scaleHeader": hex::encode(&batch.proof_seed.scale_header),
            "scaleBody": batch.proof_seed.scale_body.iter().map(hex::encode).collect::<Vec<_>>(),
            "scaleSystemEvents": hex::encode(&batch.proof_seed.scale_system_events),
            "ledgerTxHash": hex::encode(batch.candidates[0].ledger_tx_hash),
            "extrinsicIndex": batch.candidates[0].extrinsic_index,
            "requestId": &case.request_id,
            "namedCallerAddress": &case.named_caller_address,
            "stateReads": reads.as_slice(),
            "emittedEvents": events.len(),
        }))?,
    )?;
    println!(
        "LIVE_CALLER_GATE block={} hash={} ledger_tx_hash={} request_id={} expect_request={} state_reads={} events={}",
        block.number,
        block.hash,
        hex::encode(batch.candidates[0].ledger_tx_hash),
        case.request_id,
        case.expect_request,
        reads.len(),
        events.len()
    );
    Ok(())
}
