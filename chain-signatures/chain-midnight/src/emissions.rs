//! Singleton contract emissions recovered by executing transaction transcripts with the ledger VM.

use anyhow::Context as _;
use midnight_base_crypto::fab::{AlignmentAtom, AlignmentSegment};
use midnight_ledger_v9::structure::{ContractCall, ProofKind, ProofMarker, Signature, Transaction};
use midnight_onchain_runtime::context::QueryContext;
use midnight_onchain_runtime::cost_model::INITIAL_COST_MODEL;
use midnight_onchain_runtime::ops::{LogEventType, VersionedLogItem};
use midnight_onchain_runtime::result_mode::ResultModeVerify;
use midnight_onchain_runtime::state::{ChargedState, StateValue};
use midnight_storage::storage::Array;
use midnight_storage::DefaultDB;

const MISC_NAME_LEN: usize = 32;
pub const MISC_PAYLOAD_LEN: usize = 256;
const MISC_DATA_LEN: usize = MISC_NAME_LEN + MISC_PAYLOAD_LEN;
const LOG_ITEM_VERSION: u32 = 1;

const SIGN_BIDIRECTIONAL_EVENT: [u8; MISC_NAME_LEN] = padded_name(b"SignBidirectionalEvent");
const SIGNATURE_RESPONDED_EVENT: [u8; MISC_NAME_LEN] = padded_name(b"SignatureRespondedEvent");
const RESPOND_BIDIRECTIONAL_EVENT: [u8; MISC_NAME_LEN] = padded_name(b"RespondBidirectionalEvent");

const fn padded_name(text: &[u8]) -> [u8; MISC_NAME_LEN] {
    let mut padded = [0u8; MISC_NAME_LEN];
    let mut index = 0;
    while index < text.len() {
        padded[index] = text[index];
        index += 1;
    }
    padded
}

/// A decoded transaction in the proven form carried by finalized blocks.
pub type DecodedTransaction =
    Transaction<Signature, ProofMarker, <ProofMarker as ProofKind<DefaultDB>>::Pedersen, DefaultDB>;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EmissionKind {
    SignBidirectional,
    SignatureResponded,
    RespondBidirectional,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Emission {
    pub kind: EmissionKind,
    pub payload: [u8; MISC_PAYLOAD_LEN],
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SingletonCallEmissions {
    /// Position in [`DecodedTransaction::calls`] before filtering by the singleton address.
    pub call_index: u32,
    pub emissions: Vec<Emission>,
}

#[derive(Debug)]
pub(crate) struct UnsupportedFallibleCall {
    pub call_index: u32,
}

impl std::fmt::Display for UnsupportedFallibleCall {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "singleton call {} contains a fallible transcript",
            self.call_index
        )
    }
}

impl std::error::Error for UnsupportedFallibleCall {}

fn log_items<P: ProofKind<DefaultDB>>(
    call: &ContractCall<P, DefaultDB>,
) -> anyhow::Result<Vec<VersionedLogItem<DefaultDB>>> {
    let context = QueryContext::new(
        ChargedState::new(StateValue::Array(Array::new())),
        call.address,
    );
    // TODO: Consider decoding fallible transcripts when indexing supports them.
    match call.guaranteed_transcript.as_deref() {
        Some(transcript) => {
            let result = context
                .query::<ResultModeVerify>(
                    &Vec::from(&transcript.program),
                    None,
                    &INITIAL_COST_MODEL,
                )
                .context("singleton guaranteed transcript rejected by the ledger VM")?;
            Ok(result.events)
        }
        None => Ok(Vec::new()),
    }
}

fn emission_from_log_item(item: &VersionedLogItem<DefaultDB>) -> anyhow::Result<Emission> {
    anyhow::ensure!(
        item.version == LOG_ITEM_VERSION,
        "emission-schema: log item version {} is not {LOG_ITEM_VERSION}",
        item.version
    );
    anyhow::ensure!(
        item.event_type == LogEventType::Misc,
        "emission-schema: log item type {:?} is not Misc",
        item.event_type
    );

    let StateValue::Cell(cell) = &item.data else {
        anyhow::bail!("emission-schema: Misc data is not a cell");
    };
    anyhow::ensure!(
        cell.alignment.0.as_slice()
            == [AlignmentSegment::Atom(AlignmentAtom::Bytes {
                length: MISC_DATA_LEN as u32,
            })],
        "emission-schema: Misc data is not one Bytes<{MISC_DATA_LEN}> atom"
    );
    anyhow::ensure!(
        cell.value.0.len() == 1,
        "emission-schema: Misc data contains {} atoms, expected one",
        cell.value.0.len()
    );

    let stored = &cell.value.0[0].0;
    anyhow::ensure!(
        stored.len() <= MISC_DATA_LEN,
        "emission-schema: Misc data stores {} bytes under Bytes<{MISC_DATA_LEN}>",
        stored.len()
    );
    let mut bytes = [0u8; MISC_DATA_LEN];
    bytes[..stored.len()].copy_from_slice(stored);

    let mut name = [0u8; MISC_NAME_LEN];
    name.copy_from_slice(&bytes[..MISC_NAME_LEN]);
    let kind = match name {
        SIGN_BIDIRECTIONAL_EVENT => EmissionKind::SignBidirectional,
        SIGNATURE_RESPONDED_EVENT => EmissionKind::SignatureResponded,
        RESPOND_BIDIRECTIONAL_EVENT => EmissionKind::RespondBidirectional,
        _ => anyhow::bail!(
            "emission-schema: unknown singleton event name {}",
            String::from_utf8_lossy(&name)
        ),
    };

    let mut payload = [0u8; MISC_PAYLOAD_LEN];
    payload.copy_from_slice(&bytes[MISC_NAME_LEN..]);
    Ok(Emission { kind, payload })
}

/// Decode a call's raw emissions without authenticating its caller. Indexing uses
/// [`emissions_in`], which has the transaction context needed for authentication.
pub fn emissions_of_call<P: ProofKind<DefaultDB>>(
    call: &ContractCall<P, DefaultDB>,
) -> anyhow::Result<Vec<Emission>> {
    anyhow::ensure!(
        call.fallible_transcript.is_none(),
        "singleton call contains a fallible transcript"
    );
    log_items(call)?
        .iter()
        .map(emission_from_log_item)
        .collect()
}

fn verify_notification_caller(
    tx: &DecodedTransaction,
    segment: u16,
    call_index: u32,
    callee: &ContractCall<ProofMarker, DefaultDB>,
    notification: &crate::records::SignBidirectionalEventNotification,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        callee.entry_point.0 == b"signBidirectional",
        "notification emitted by a different entry point"
    );
    let key = (
        callee.address,
        callee.entry_point.ep_hash(),
        callee.communication_commitment,
    );
    let mut callee_count = 0;
    let mut claimant = None;
    for (index, (caller_segment, caller)) in tx.calls().enumerate() {
        if caller_segment != segment {
            continue;
        }
        if (
            caller.address,
            caller.entry_point.ep_hash(),
            caller.communication_commitment,
        ) == key
        {
            callee_count += 1;
        }
        // `ContractCall::calls_with_seq` returns only the first match. Count the
        // native claims across both phases so competing claims cannot be hidden.
        for (transcript, guaranteed) in caller
            .guaranteed_transcript
            .iter()
            .map(|t| (t, true))
            .chain(caller.fallible_transcript.iter().map(|t| (t, false)))
        {
            for claim in transcript.effects.claimed_contract_calls.iter() {
                let (_, address, entry_point, commitment) = claim.into_inner();
                if (address, entry_point, commitment) == key {
                    anyhow::ensure!(claimant.is_none(), "multiple claims for notification call");
                    claimant = Some((index, caller.address, guaranteed));
                }
            }
        }
    }
    anyhow::ensure!(callee_count == 1, "ambiguous notification callee identity");
    let (index, address, guaranteed) = claimant.context("notification call has no caller claim")?;
    anyhow::ensure!(
        guaranteed && index < call_index as usize,
        "caller claim has invalid phase or order"
    );
    anyhow::ensure!(
        address.0 .0 == notification.payload[..32],
        "notification names a different caller"
    );
    Ok(())
}

/// Extract from a proof-validated, applied transaction at the finalized-block boundary.
/// The singleton circuit commits to its request ID and notification arguments and
/// emits those same bytes; ledger proofs bind that commitment to this call's transcript.
/// This filters caller claims, relying on the node's proof validation, not re-verifying it.
pub fn emissions_in(
    tx: &DecodedTransaction,
    singleton: &[u8; 32],
) -> anyhow::Result<Vec<SingletonCallEmissions>> {
    tx.calls()
        .enumerate()
        .filter(|(_, (_, call))| call.address.0 .0 == *singleton)
        .map(|(call_index, (segment, call))| {
            let call_index = u32::try_from(call_index)
                .context("transaction contains more calls than a u32 locator can represent")?;
            if call.fallible_transcript.is_some() {
                return Err(anyhow::Error::new(UnsupportedFallibleCall { call_index }));
            }
            let mut emissions = emissions_of_call(&call)?;
            let emission_count = emissions.len();
            emissions.retain(|emission| {
                if emission.kind != EmissionKind::SignBidirectional {
                    return true;
                }
                let notification = crate::reader::decode_notification(&emission.payload);
                let verification = if emission_count != 1 {
                    Err(anyhow::anyhow!(
                        "signBidirectional must emit exactly one notification"
                    ))
                } else {
                    verify_notification_caller(tx, segment, call_index, &call, &notification)
                };
                if let Err(error) = verification {
                    tracing::warn!(
                        reason = "notification-caller-unverified",
                        call_index,
                        request_id = %hex::encode(notification.request_id),
                        "midnight notification dropped: {error:#}"
                    );
                    return false;
                }
                true
            });
            Ok(SingletonCallEmissions {
                call_index,
                emissions,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test_utils::{array_of, cell_from_atoms, hex_32, trim};
    use midnight_base_crypto::cost_model::RunningCost;
    use midnight_base_crypto::time::Timestamp;
    use midnight_ledger_v9::structure::{
        ContractAction, ContractCall, Intent, ProofMarker, ProofVersioned, StandardTransaction,
    };
    use midnight_onchain_runtime::context::Effects;
    use midnight_onchain_runtime::ops::{LogEventType, Op, VersionedLogItem};
    use midnight_onchain_runtime::result_mode::ResultModeVerify;
    use midnight_onchain_runtime::state::{EntryPointBuf, StateValue};
    use midnight_onchain_runtime::transcript::Transcript;
    use midnight_storage::arena::Sp;
    use midnight_storage::storage::{Array, HashMap};
    use midnight_storage::DefaultDB;
    use midnight_transient_crypto::commitment::PureGeneratorPedersen;
    use midnight_transient_crypto::curve::{EmbeddedFr, Fr};
    use midnight_transient_crypto::proofs::Proof;

    type TestOp = Op<ResultModeVerify, DefaultDB>;

    const SINGLETON: [u8; 32] = [0x12; 32];
    const OTHER_CONTRACT: [u8; 32] = [0x34; 32];
    const GUARANTEED: [u8; MISC_PAYLOAD_LEN] = [0xa1; MISC_PAYLOAD_LEN];
    const FALLIBLE: [u8; MISC_PAYLOAD_LEN] = [0xf2; MISC_PAYLOAD_LEN];
    const CAPTURE_SINGLETON: &str =
        "b116cd0482b84922e761278a25d1ee2305fd6d630f0d48954d2af6537f8e214e";
    const CAPTURE_REQUEST_ID: &str =
        "1cd10eb1f4fa5c665084d24a7982b09aa321886dce77d85b5f6feee0687a414b";
    const NOTIFY_TX_156: &[u8] = include_bytes!("../fixtures/notify-tx-156.mn");
    const RESPOND_TX_161: &[u8] = include_bytes!("../fixtures/respond-tx-161.mn");
    const RESPOND_BIDIRECTIONAL_TX_181: &[u8] =
        include_bytes!("../fixtures/respond-bidirectional-tx-181.mn");

    const fn padded_name(text: &[u8]) -> [u8; MISC_NAME_LEN] {
        let mut padded = [0u8; MISC_NAME_LEN];
        let mut index = 0;
        while index < text.len() {
            padded[index] = text[index];
            index += 1;
        }
        padded
    }

    fn data_cell(name: &[u8; MISC_NAME_LEN], payload: &[u8], width: u32) -> StateValue<DefaultDB> {
        let mut bytes = name.to_vec();
        bytes.extend_from_slice(payload);
        cell_from_atoms(&[trim(&bytes)], &[width])
    }

    fn raw_log_item(
        version: u32,
        event_type: u8,
        data: StateValue<DefaultDB>,
    ) -> StateValue<DefaultDB> {
        array_of(vec![
            cell_from_atoms(&[trim(&version.to_le_bytes())], &[4]),
            cell_from_atoms(&[trim(&[event_type])], &[1]),
            data,
        ])
    }

    fn logging(value: StateValue<DefaultDB>) -> Vec<TestOp> {
        vec![
            Op::Push {
                storage: false,
                value,
            },
            Op::Log,
        ]
    }

    fn emit_ops(name: [u8; MISC_NAME_LEN], payload: [u8; MISC_PAYLOAD_LEN]) -> Vec<TestOp> {
        logging(raw_log_item(
            1,
            LogEventType::Misc as u8,
            data_cell(&name, &payload, (MISC_NAME_LEN + MISC_PAYLOAD_LEN) as u32),
        ))
    }

    fn transcript(ops: Vec<TestOp>) -> Transcript<DefaultDB> {
        Transcript {
            gas: RunningCost::default(),
            effects: Effects::default(),
            program: Array::new_from_slice(&ops),
            version: None,
        }
    }

    fn call(
        address: [u8; 32],
        guaranteed: Option<Vec<TestOp>>,
        fallible: Option<Vec<TestOp>>,
    ) -> ContractCall<ProofMarker, DefaultDB> {
        let mut call = ContractCall {
            address: Default::default(),
            entry_point: EntryPointBuf(b"test".to_vec()),
            guaranteed_transcript: guaranteed.map(|ops| Sp::new(transcript(ops))),
            fallible_transcript: fallible.map(|ops| Sp::new(transcript(ops))),
            communication_commitment: Fr::default(),
            proof: ProofVersioned::V2(Proof(Vec::new())),
        };
        call.address.0 .0 = address;
        call
    }

    fn transaction(calls: Vec<ContractCall<ProofMarker, DefaultDB>>) -> DecodedTransaction {
        let actions: Vec<ContractAction<ProofMarker, DefaultDB>> =
            calls.into_iter().map(ContractAction::from).collect();
        let intent = Intent {
            guaranteed_unshielded_offer: None,
            fallible_unshielded_offer: None,
            actions: Array::new_from_slice(&actions),
            dust_actions: None,
            ttl: Timestamp::from_secs(0),
            binding_commitment: PureGeneratorPedersen::largest_representable(),
        };
        midnight_ledger_v9::structure::Transaction::Standard(StandardTransaction {
            network_id: "undeployed".to_string(),
            intents: HashMap::new().insert(1u16, intent),
            guaranteed_coins: None,
            fallible_coins: HashMap::new(),
            binding_randomness: EmbeddedFr::default(),
        })
    }

    fn one_item(
        version: u32,
        event_type: LogEventType,
        data: StateValue<DefaultDB>,
    ) -> VersionedLogItem<DefaultDB> {
        VersionedLogItem {
            version,
            event_type,
            data,
        }
    }

    fn captured_notify_calls() -> Vec<ContractCall<ProofMarker, DefaultDB>> {
        let tx: DecodedTransaction =
            midnight_serialize::tagged_deserialize(&mut &NOTIFY_TX_156[..]).unwrap();
        let calls: Vec<_> = tx.calls().map(|(_, call)| call).collect();
        assert_eq!(calls.len(), 2);
        assert!(calls[0].calls(&calls[1]));
        calls
    }

    // These derivatives exercise structural rejection, not valid fresh proofs.
    fn changed_notify(
        edit: impl FnOnce(&mut Vec<ContractCall<ProofMarker, DefaultDB>>),
    ) -> DecodedTransaction {
        let mut calls = captured_notify_calls();
        edit(&mut calls);
        transaction(calls)
    }

    fn edit_claim(
        caller: &mut ContractCall<ProofMarker, DefaultDB>,
        edit: impl FnOnce(&mut midnight_onchain_runtime::context::ClaimedContractCallsValue),
    ) {
        let mut transcript = caller.guaranteed_transcript.as_deref().unwrap().clone();
        assert_eq!(transcript.effects.claimed_contract_calls.size(), 1);
        let mut claim = (**transcript
            .effects
            .claimed_contract_calls
            .iter()
            .next()
            .unwrap())
        .clone();
        edit(&mut claim);
        transcript.effects.claimed_contract_calls = Default::default();
        transcript.effects.claimed_contract_calls =
            transcript.effects.claimed_contract_calls.insert(claim);
        caller.guaranteed_transcript = Some(Sp::new(transcript));
    }

    fn edit_captured_payload(
        call: &mut ContractCall<ProofMarker, DefaultDB>,
        edit: impl FnOnce(&mut [u8]),
    ) {
        let mut transcript = call.guaranteed_transcript.as_deref().unwrap().clone();
        let mut program = Vec::from(&transcript.program);
        let Op::Push {
            value: StateValue::Array(event),
            ..
        } = &mut program[0]
        else {
            panic!("captured notification starts by pushing its event envelope");
        };
        let mut envelope = Vec::from(&*event);
        let StateValue::Cell(cell) = &envelope[2] else {
            panic!("captured Misc data cell")
        };
        let mut cell = (**cell).clone();
        assert_eq!(cell.value.0.len(), 1);
        assert_eq!(
            cell.alignment.0.as_slice(),
            &[AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 288 })]
        );
        let bytes = &mut cell.value.0[0].0;
        bytes.resize(MISC_DATA_LEN, 0);
        assert_eq!(&bytes[..MISC_NAME_LEN], &SIGN_BIDIRECTIONAL_EVENT);
        edit(&mut bytes[MISC_NAME_LEN..]);
        *bytes = trim(bytes);
        envelope[2] = StateValue::from(cell);
        *event = Array::new_from_slice(&envelope);
        transcript.program = Array::new_from_slice(&program);
        call.guaranteed_transcript = Some(Sp::new(transcript));
    }

    #[test]
    fn decodes_each_singleton_event_kind() {
        for (name, expected) in [
            (
                padded_name(b"SignBidirectionalEvent"),
                EmissionKind::SignBidirectional,
            ),
            (
                padded_name(b"SignatureRespondedEvent"),
                EmissionKind::SignatureResponded,
            ),
            (
                padded_name(b"RespondBidirectionalEvent"),
                EmissionKind::RespondBidirectional,
            ),
        ] {
            let item = one_item(1, LogEventType::Misc, data_cell(&name, &GUARANTEED, 288));
            assert_eq!(
                emission_from_log_item(&item).unwrap(),
                Emission {
                    kind: expected,
                    payload: GUARANTEED,
                }
            );
        }
    }

    #[test]
    fn caller_binding_rejects_direct_singleton_notification() {
        let captured: DecodedTransaction =
            midnight_serialize::tagged_deserialize(&mut &NOTIFY_TX_156[..]).unwrap();
        let singleton = hex_32(CAPTURE_SINGLETON);
        let direct = transaction(
            captured
                .calls()
                .map(|(_, call)| call)
                .filter(|call| call.address.0 .0 == singleton)
                .collect(),
        );
        let calls = emissions_in(&direct, &singleton).unwrap();
        assert!(
            calls
                .iter()
                .flat_map(|call| &call.emissions)
                .all(|emission| { emission.kind != EmissionKind::SignBidirectional }),
            "a direct singleton call must not authorize a signature request"
        );
    }

    #[test]
    fn caller_binding_rejects_duplicate_callee_identity() {
        let captured: DecodedTransaction =
            midnight_serialize::tagged_deserialize(&mut &NOTIFY_TX_156[..]).unwrap();
        let mut calls: Vec<_> = captured.calls().map(|(_, call)| call).collect();
        assert_eq!(calls.len(), 2);
        assert!(calls[0].calls(&calls[1]));
        calls.push(calls[1].clone());
        let decoded = emissions_in(&transaction(calls), &hex_32(CAPTURE_SINGLETON)).unwrap();
        assert!(decoded.iter().all(|call| call.emissions.is_empty()));
    }

    #[test]
    fn caller_binding_rejects_duplicate_claims_from_one_caller() {
        let captured: DecodedTransaction =
            midnight_serialize::tagged_deserialize(&mut &NOTIFY_TX_156[..]).unwrap();
        let mut calls: Vec<_> = captured.calls().map(|(_, call)| call).collect();
        let mut transcript = calls[0].guaranteed_transcript.as_deref().unwrap().clone();
        let (seq, address, entry_point, commitment) = transcript
            .effects
            .claimed_contract_calls
            .iter()
            .next()
            .unwrap()
            .into_inner();
        transcript.effects.claimed_contract_calls =
            transcript.effects.claimed_contract_calls.insert(
                midnight_onchain_runtime::context::ClaimedContractCallsValue::from_inner(
                    seq + 1,
                    address,
                    entry_point,
                    commitment,
                ),
            );
        assert_eq!(transcript.effects.claimed_contract_calls.size(), 2);
        calls[0].guaranteed_transcript = Some(Sp::new(transcript));
        assert!(
            calls[0].calls(&calls[1]),
            "the first-match SDK helper hides ambiguity"
        );
        let decoded = emissions_in(&transaction(calls), &hex_32(CAPTURE_SINGLETON)).unwrap();
        assert!(decoded.iter().all(|call| call.emissions.is_empty()));
    }

    #[test]
    fn caller_binding_rejects_multiple_notifications_in_one_call() {
        let captured: DecodedTransaction =
            midnight_serialize::tagged_deserialize(&mut &NOTIFY_TX_156[..]).unwrap();
        let mut calls: Vec<_> = captured.calls().map(|(_, call)| call).collect();
        let mut transcript = calls[1].guaranteed_transcript.as_deref().unwrap().clone();
        let program = Vec::from(&transcript.program);
        transcript.program = Array::new_from_slice(&[program.clone(), program].concat());
        calls[1].guaranteed_transcript = Some(Sp::new(transcript));
        assert_eq!(emissions_of_call(&calls[1]).unwrap().len(), 2);
        let decoded = emissions_in(&transaction(calls), &hex_32(CAPTURE_SINGLETON)).unwrap();
        assert!(decoded.iter().all(|call| call.emissions.is_empty()));
    }

    #[test]
    fn caller_binding_requires_the_exact_unique_guaranteed_predecessor() {
        for (case, tx) in [
            (
                "mismatched caller",
                changed_notify(|calls| calls[0].address.0 .0 = OTHER_CONTRACT),
            ),
            (
                "unrelated named caller",
                changed_notify(|calls| {
                    let mut actual_caller = calls[0].clone();
                    actual_caller.address.0 .0 = OTHER_CONTRACT;
                    let mut transcript = calls[0].guaranteed_transcript.as_deref().unwrap().clone();
                    transcript.effects.claimed_contract_calls = Default::default();
                    calls[0].guaranteed_transcript = Some(Sp::new(transcript));
                    calls.insert(0, actual_caller);
                }),
            ),
            (
                "wrong commitment",
                changed_notify(|calls| {
                    assert_ne!(calls[1].communication_commitment, Fr::from(1));
                    calls[1].communication_commitment = Fr::from(1);
                }),
            ),
            (
                "wrong claimed callee",
                changed_notify(|calls| {
                    edit_claim(&mut calls[0], |claim| claim.1 .0 .0 = OTHER_CONTRACT)
                }),
            ),
            (
                "wrong claimed entry point",
                changed_notify(|calls| {
                    edit_claim(&mut calls[0], |claim| {
                        claim.2 = EntryPointBuf(b"respond".to_vec()).ep_hash()
                    })
                }),
            ),
            (
                "linked wrong entry point",
                changed_notify(|calls| {
                    calls[1].entry_point = EntryPointBuf(b"respond".to_vec());
                    let ep = calls[1].entry_point.ep_hash();
                    edit_claim(&mut calls[0], |claim| claim.2 = ep);
                    assert!(calls[0].calls(&calls[1]));
                }),
            ),
            (
                "competing foreign claimant",
                changed_notify(|calls| {
                    let mut competitor = calls[0].clone();
                    competitor.address.0 .0 = OTHER_CONTRACT;
                    calls.insert(0, competitor);
                }),
            ),
            (
                "competing fallible claim",
                changed_notify(|calls| {
                    calls[0].fallible_transcript = calls[0].guaranteed_transcript.clone()
                }),
            ),
            (
                "fallible-only claim",
                changed_notify(|calls| {
                    calls[0].fallible_transcript = calls[0].guaranteed_transcript.take()
                }),
            ),
            (
                "caller after callee",
                changed_notify(|calls| calls.swap(0, 1)),
            ),
            (
                "missing claim",
                changed_notify(|calls| calls[0].guaranteed_transcript = None),
            ),
            (
                "notification names another caller",
                changed_notify(|calls| {
                    edit_captured_payload(&mut calls[1], |payload| payload[33] ^= 1)
                }),
            ),
        ] {
            let decoded = emissions_in(&tx, &hex_32(CAPTURE_SINGLETON)).unwrap();
            assert_eq!(decoded.len(), 1, "{case}: still locates the singleton");
            assert!(
                decoded[0].emissions.is_empty(),
                "{case}: must reject notification"
            );
        }
    }

    #[test]
    fn caller_binding_does_not_join_across_intents() {
        let mut calls = captured_notify_calls();
        let callee = calls.pop().unwrap();
        let Transaction::Standard(mut tx) = transaction(calls) else {
            unreachable!()
        };
        let Transaction::Standard(other) = transaction(vec![callee]) else {
            unreachable!()
        };
        tx.intents = tx
            .intents
            .insert(2, (*other.intents.get(&1).unwrap()).clone());
        let decoded = emissions_in(&Transaction::Standard(tx), &hex_32(CAPTURE_SINGLETON)).unwrap();
        assert_eq!(decoded.len(), 1);
        assert!(decoded[0].emissions.is_empty());

        let Transaction::Standard(mut tx) = transaction(captured_notify_calls()) else {
            unreachable!()
        };
        tx.intents = tx.intents.insert(2, (*tx.intents.get(&1).unwrap()).clone());
        let decoded = emissions_in(&Transaction::Standard(tx), &hex_32(CAPTURE_SINGLETON)).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].call_index, 1);
        assert_eq!(decoded[1].call_index, 3);
        assert_eq!(decoded[0].emissions.len(), 1);
        assert_eq!(decoded[0].emissions, decoded[1].emissions);
    }

    #[test]
    fn caller_binding_keeps_distinct_calls_and_response_locators_independent() {
        let mut calls = captured_notify_calls();
        let mut second = calls.clone();
        second[1].communication_commitment = Fr::from(1);
        edit_claim(&mut second[0], |claim| claim.3 = Fr::from(1));
        edit_captured_payload(&mut second[1], |payload| payload[1] ^= 1);
        let first_emissions = emissions_of_call(&calls[1]).unwrap();
        let second_emissions = emissions_of_call(&second[1]).unwrap();
        assert_ne!(first_emissions, second_emissions);
        calls.extend(second);
        let mut unlinked = calls[1].clone();
        unlinked.communication_commitment = Fr::from(2);
        calls.push(unlinked);
        let response: DecodedTransaction =
            midnight_serialize::tagged_deserialize(&mut &RESPOND_TX_161[..]).unwrap();
        let response = response.calls().next().unwrap().1;
        let response_emissions = emissions_of_call(&response).unwrap();
        calls.push(response);
        assert_eq!(
            emissions_in(&transaction(calls), &hex_32(CAPTURE_SINGLETON)).unwrap(),
            vec![
                SingletonCallEmissions {
                    call_index: 1,
                    emissions: first_emissions
                },
                SingletonCallEmissions {
                    call_index: 3,
                    emissions: second_emissions
                },
                SingletonCallEmissions {
                    call_index: 4,
                    emissions: vec![]
                },
                SingletonCallEmissions {
                    call_index: 5,
                    emissions: response_emissions
                },
            ]
        );
    }

    #[test]
    fn captured_proof_binds_request_id_and_every_notification_argument() {
        use midnight_transient_crypto::proofs::{VerifierKey, PARAMS_VERIFIER};

        let captured: DecodedTransaction =
            midnight_serialize::tagged_deserialize(&mut &NOTIFY_TX_156[..]).unwrap();
        let (_, intent) = captured
            .intents()
            .find(|(_, intent)| {
                intent
                    .calls()
                    .any(|call| call.entry_point.0 == b"signBidirectional")
            })
            .unwrap();
        let callee = intent
            .calls()
            .find(|call| call.entry_point.0 == b"signBidirectional")
            .unwrap();
        let key: VerifierKey = midnight_serialize::tagged_deserialize(
            &mut &include_bytes!("../fixtures/notify-signBidirectional.verifier")[..],
        )
        .unwrap();
        let ProofVersioned::V3(proof) = &callee.proof else {
            panic!("captured V3 proof")
        };
        let inputs = callee.public_inputs(intent.binding_commitment.clone().into());
        // Call the cryptographic verifier directly: the ledger crate's optional
        // proof-verifying feature is disabled in this integration.
        key.verify(&PARAMS_VERIFIER, proof, inputs.clone().into_iter())
            .unwrap();
        for (case, offsets) in [
            ("requestId", vec![1]),
            ("version", vec![0]),
            ("caller", vec![33]),
            ("ledger path", vec![66]),
            ("notification padding", vec![160]),
            (
                "entire notification",
                std::iter::once(0).chain(33..161).collect(),
            ),
        ] {
            let mut altered = callee.clone();
            edit_captured_payload(&mut altered, |payload| {
                for offset in &offsets {
                    payload[*offset] ^= 1;
                }
            });
            let changed = altered.public_inputs(intent.binding_commitment.clone().into());
            assert_ne!(
                emissions_of_call(&altered).unwrap(),
                emissions_of_call(callee).unwrap(),
                "{case}"
            );
            assert_ne!(
                changed, inputs,
                "{case}: mutation reaches the public transcript"
            );
            assert_eq!(changed[0], inputs[0], "{case}: binding input unchanged");
            assert_eq!(
                altered.communication_commitment,
                callee.communication_commitment
            );
            assert!(
                key.verify(&PARAMS_VERIFIER, proof, changed.into_iter())
                    .is_err(),
                "{case}"
            );
            assert_eq!(
                callee.public_inputs(intent.binding_commitment.clone().into()),
                inputs
            );
        }
        key.verify(&PARAMS_VERIFIER, proof, inputs.into_iter())
            .unwrap();
    }

    #[test]
    fn captured_transactions_decode_the_three_singleton_emissions() {
        let singleton = hex_32(CAPTURE_SINGLETON);
        let request_id = hex_32(CAPTURE_REQUEST_ID);

        for (name, bytes, expected_kind, expected_call_index, rid_offset) in [
            (
                "notify-tx-156",
                NOTIFY_TX_156,
                EmissionKind::SignBidirectional,
                1,
                1,
            ),
            (
                "respond-tx-161",
                RESPOND_TX_161,
                EmissionKind::SignatureResponded,
                0,
                0,
            ),
            (
                "respond-bidirectional-tx-181",
                RESPOND_BIDIRECTIONAL_TX_181,
                EmissionKind::RespondBidirectional,
                0,
                0,
            ),
        ] {
            let tx: DecodedTransaction = midnight_serialize::tagged_deserialize(&mut &bytes[..])
                .unwrap_or_else(|err| panic!("{name}: captured transaction must decode: {err}"));
            let calls = emissions_in(&tx, &singleton)
                .unwrap_or_else(|err| panic!("{name}: singleton emissions must decode: {err:#}"));
            let [call] = calls.as_slice() else {
                panic!("{name}: expected exactly one singleton call, got {calls:?}");
            };
            assert_eq!(call.call_index, expected_call_index, "{name}: call index");
            let [emission] = call.emissions.as_slice() else {
                panic!(
                    "{name}: expected exactly one singleton emission, got {:?}",
                    call.emissions
                );
            };
            assert_eq!(emission.kind, expected_kind, "{name}: event kind");
            assert_eq!(
                emission.payload[rid_offset..rid_offset + request_id.len()],
                request_id,
                "{name}: request id at the event-specific payload offset"
            );
        }
    }

    #[test]
    fn rejects_fallible_singleton_calls() {
        let tx = transaction(vec![call(
            SINGLETON,
            Some(emit_ops(padded_name(b"SignBidirectionalEvent"), GUARANTEED)),
            Some(emit_ops(padded_name(b"SignatureRespondedEvent"), FALLIBLE)),
        )]);

        let err = emissions_in(&tx, &SINGLETON)
            .expect_err("a fallible singleton call is outside the supported integration contract");
        let unsupported = err
            .downcast_ref::<UnsupportedFallibleCall>()
            .unwrap_or_else(|| panic!("unexpected rejection: {err:#}"));
        assert_eq!(unsupported.call_index, 0);
    }

    #[test]
    fn rejects_singleton_event_schema_drift() {
        let known_name = padded_name(b"SignBidirectionalEvent");
        let foreign_name = padded_name(b"ForeignEvent");
        for (case, logged_value) in [
            (
                "foreign name",
                raw_log_item(
                    1,
                    LogEventType::Misc as u8,
                    data_cell(&foreign_name, &GUARANTEED, 288),
                ),
            ),
            (
                "version two",
                raw_log_item(
                    2,
                    LogEventType::Misc as u8,
                    data_cell(&known_name, &GUARANTEED, 288),
                ),
            ),
            (
                "event type nine",
                raw_log_item(
                    1,
                    LogEventType::Unpaused as u8,
                    data_cell(&known_name, &GUARANTEED, 288),
                ),
            ),
            (
                "Bytes<256>",
                raw_log_item(
                    1,
                    LogEventType::Misc as u8,
                    data_cell(&known_name, &GUARANTEED[..224], 256),
                ),
            ),
            (
                "version-zero VM fallback",
                data_cell(&known_name, &GUARANTEED, 288),
            ),
        ] {
            let tx = transaction(vec![call(SINGLETON, Some(logging(logged_value)), None)]);
            let error = emissions_in(&tx, &SINGLETON).unwrap_err();
            assert!(
                error.to_string().contains("emission-schema"),
                "{case}: {error:#}"
            );
        }
    }

    #[test]
    fn the_vm_rejects_log_without_a_pushed_value() {
        let tx = transaction(vec![call(SINGLETON, Some(vec![Op::Log]), None)]);

        assert!(emissions_in(&tx, &SINGLETON).is_err());
    }

    #[test]
    fn ignores_foreign_calls_but_preserves_transaction_call_indices() {
        let tx = transaction(vec![
            call(
                OTHER_CONTRACT,
                Some(emit_ops(padded_name(b"SignBidirectionalEvent"), GUARANTEED)),
                None,
            ),
            call(
                SINGLETON,
                Some(emit_ops(
                    padded_name(b"RespondBidirectionalEvent"),
                    FALLIBLE,
                )),
                None,
            ),
        ]);

        assert_eq!(
            emissions_in(&tx, &SINGLETON).unwrap(),
            vec![SingletonCallEmissions {
                call_index: 1,
                emissions: vec![Emission {
                    kind: EmissionKind::RespondBidirectional,
                    payload: FALLIBLE,
                }],
            }]
        );
    }

    #[test]
    fn retains_a_silent_singleton_call() {
        let tx = transaction(vec![call(SINGLETON, None, None)]);

        assert_eq!(
            emissions_in(&tx, &SINGLETON).unwrap(),
            vec![SingletonCallEmissions {
                call_index: 0,
                emissions: Vec::new(),
            }]
        );
    }
}
