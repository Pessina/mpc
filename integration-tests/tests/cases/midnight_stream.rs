use std::time::Duration;

use alloy::primitives::{keccak256, Address, Bytes, U256};
use alloy::providers::ext::AnvilApi as _;
use alloy::providers::{Provider as _, ProviderBuilder};
use anyhow::Context as _;
use integration_tests::cluster;
use integration_tests::midnight::{CallerNotification, FinalizedCallerTransaction};
use mpc_chain_integration_core::utils::test::ChainIndexerStream;
use mpc_chain_integration_core::{MockStateManager, NoopChainTelemetry};
use mpc_chain_midnight::MidnightIndexer;
use mpc_node::sign_bidirectional::{derive_user_address, SignBidirectionalEventExt as _};
use mpc_primitives::{Chain, ChainEvent, SignKind};
use serial_test::serial;
use test_log::test;

const EVENT_TIMEOUT: Duration = Duration::from_secs(8 * 60);
const RETURN_TRUE_RUNTIME_BYTECODE: &str = "600160005260206000f3";

fn assert_applied(receipt: &FinalizedCallerTransaction, request_id: &[u8; 32]) {
    assert_eq!(receipt.status, "SucceedEntirely");
    assert_eq!(receipt.request_id, hex::encode(request_id));
    assert!(!receipt.tx_id.is_empty());
    assert!(!receipt.block_hash.is_empty());
    tracing::info!(?receipt, "caller verification transaction finalized");
}

async fn assert_no_request_through(
    events: &mut ChainIndexerStream,
    request_id: [u8; 32],
    height: u64,
) -> anyhow::Result<()> {
    tokio::time::timeout(EVENT_TIMEOUT, async {
        loop {
            let event = events
                .next_event()
                .await
                .context("Midnight stream closed")?;
            match event {
                ChainEvent::SignRequest { request, .. } => {
                    anyhow::ensure!(
                        request.id.request_id != request_id,
                        "unauthenticated notification emitted SignRequest for {}",
                        hex::encode(request_id)
                    );
                }
                ChainEvent::Block(processed) if processed >= height => {
                    tracing::info!(
                        request_id = %hex::encode(request_id),
                        height,
                        processed,
                        "caller rejection observation reached finalized processing"
                    );
                    return Ok(());
                }
                _ => {}
            }
        }
    })
    .await
    .context("waiting for finalized caller rejection observation")?
}

async fn wait_for_completed_checkpoint(
    cluster: &cluster::Cluster,
    request_id: [u8; 32],
    minimum_height: u64,
) -> anyhow::Result<()> {
    tokio::time::timeout(EVENT_TIMEOUT, async {
        loop {
            let mut complete = true;
            for node in 0..cluster.len() {
                match cluster.nodes.fetch_checkpoint(node, Chain::Midnight).await {
                    Ok(checkpoint) => {
                        complete &= checkpoint.block_height >= minimum_height
                            && checkpoint
                                .pending_requests
                                .iter()
                                .all(|pending| pending.sign_id().request_id != request_id);
                    }
                    Err(_) => complete = false,
                }
            }
            if complete {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    })
    .await
    .context("timed out waiting for every MPC node to checkpoint final Midnight completion")??;
    Ok(())
}

#[ignore = "starts a real Midnight node, indexer, proof server, Anvil, and MPC cluster"]
#[serial]
#[test(tokio::test)]
async fn midnight_to_ethereum_to_midnight_consumes_caller_response() -> anyhow::Result<()> {
    let cluster = cluster::spawn().ethereum().midnight().await?;
    cluster.wait().signable().await?;
    let midnight = cluster
        .midnight
        .as_ref()
        .context("Midnight context was not started")?;
    let indexer = MidnightIndexer::new(
        midnight.config.clone(),
        MockStateManager::new(),
        NoopChainTelemetry,
    )
    .await?;
    let mut events = ChainIndexerStream::start(indexer, EVENT_TIMEOUT).await?;

    let ethereum = cluster
        .nodes
        .ctx()
        .ethereum
        .as_ref()
        .context("Ethereum context was not started")?;
    let anvil =
        ProviderBuilder::new().connect_http(ethereum.sandbox.external_http_endpoint.parse()?);
    let target = Address::repeat_byte(0x42);
    anvil
        .anvil_set_code(
            target,
            Bytes::from(hex::decode(RETURN_TRUE_RUNTIME_BYTECODE)?),
        )
        .await?;

    let mut argument = [0; 32];
    argument[31] = 6;
    let stored = midnight
        .store_is_even(0, target.into_array(), argument)
        .await?;
    let stored_id: [u8; 32] = hex::decode(&stored.request_id)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("stored request ID is not 32 bytes"))?;
    assert_applied(&stored, &stored_id);
    assert_no_request_through(&mut events, stored_id, stored.block_height).await?;
    for notification in [CallerNotification::Direct, CallerNotification::WrongCaller] {
        let denied = midnight
            .notify_request(notification, &stored.request_id)
            .await?;
        assert_applied(&denied, &stored_id);
        assert_no_request_through(&mut events, stored_id, denied.block_height + 2).await?;
        wait_for_completed_checkpoint(&cluster, stored_id, denied.block_height + 2).await?;
    }
    let linked = midnight
        .notify_request(CallerNotification::Linked, &stored.request_id)
        .await?;
    assert_applied(&linked, &stored_id);
    let ChainEvent::SignRequest { request, .. } = events
        .wait_for(
            |event| {
                matches!(
                    event,
                    ChainEvent::SignRequest { request, .. }
                        if request.chain == Chain::Midnight
                            && request.id.request_id == stored_id
                            && matches!(request.kind, SignKind::SignBidirectional(_))
                )
            },
            EVENT_TIMEOUT,
        )
        .await
        .context("waiting for the caller SignRequest")?
    else {
        unreachable!("filtered above")
    };
    let request_id = request.id.request_id;
    let SignKind::SignBidirectional(sign_event) = &request.kind else {
        unreachable!("filtered above")
    };
    assert_eq!(sign_event.caip2_id, Chain::Ethereum.caip2_chain_id());

    events
        .wait_for(
            |event| matches!(event, ChainEvent::Respond(response) if response.request_id == request_id),
            EVENT_TIMEOUT,
        )
        .await
        .context("waiting for the finalized respond entry")?;
    let root_public_key =
        mpc_crypto::near_public_key_to_affine_point(cluster.root_public_key().await?);
    let expected_sender = derive_user_address(root_public_key, sign_event.epsilon()?);
    let signed = midnight
        .signed_evm_transaction(request_id, &format!("{expected_sender:#x}"))
        .await?;
    assert_eq!(signed.from.parse::<Address>()?, expected_sender);
    assert_eq!(signed.to.parse::<Address>()?, target);
    assert_eq!(signed.chain_id, "31337");
    assert_eq!(
        signed.unsigned_hash,
        format!("{:#x}", keccak256(&sign_event.serialized_transaction))
    );
    tracing::info!(
        request_id = %hex::encode(request_id),
        expected_sender = %expected_sender,
        unsigned_hash = %signed.unsigned_hash,
        signed_transaction = %signed.serialized,
        "verified MPC signature for authenticated caller request"
    );
    let mut expected_input = hex::decode("2a2e1320")?;
    expected_input.extend_from_slice(&argument);
    assert_eq!(
        hex::decode(signed.data.trim_start_matches("0x"))?,
        expected_input
    );
    anvil
        .anvil_set_balance(expected_sender, U256::from(10_000_000_000_000_000_000u128))
        .await?;
    let pending = anvil
        .send_raw_transaction(&hex::decode(signed.serialized.trim_start_matches("0x"))?)
        .await?;
    let receipt = pending.get_receipt().await?;
    anyhow::ensure!(receipt.status(), "the MPC-signed EVM transaction reverted");

    events
        .wait_for(
            |event| {
                matches!(
                    event,
                    ChainEvent::RespondBidirectional(response) if response.request_id == request_id
                )
            },
            EVENT_TIMEOUT,
        )
        .await
        .context("waiting for the finalized respondBidirectional entry")?;
    midnight.settle_response(request_id).await?;
    let ChainEvent::Block(final_block) = events
        .wait_for(|event| matches!(event, ChainEvent::Block(_)), EVENT_TIMEOUT)
        .await
        .context("waiting for a block after respondBidirectional")?
    else {
        unreachable!("filtered above")
    };
    wait_for_completed_checkpoint(&cluster, request_id, final_block).await?;
    midnight.shutdown().await?;
    Ok(())
}
