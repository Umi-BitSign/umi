//! Read Timestamp.Now through the same pinned follow subscription as its header.
//!
//! Storage progress shares the follow stream with chain notifications. Preserve
//! those notifications in order while waiting for the exact storage operation.

use std::collections::VecDeque;

use futures_util::StreamExt;
use serde_json::{Value, value::RawValue};
use subxt_lightclient::{LightClientRpc, LightClientRpcSubscription};

use crate::{
    ObserverError, RPC_TIMEOUT, TIMESTAMP_NOW_KEY, TIMESTAMP_RETRY_DELAY, TIMESTAMP_RPC_ATTEMPTS,
    decode_timestamp, rpc_value, rpc_with_deadline,
};

const MAXIMUM_PENDING_EVENTS: usize = 256;
const MAXIMUM_PENDING_BYTES: usize = 1024 * 1024;

#[derive(Default)]
pub(crate) struct PendingEvents {
    events: VecDeque<Box<RawValue>>,
    bytes: usize,
}

impl PendingEvents {
    pub(crate) fn pop(&mut self) -> Option<Box<RawValue>> {
        let raw = self.events.pop_front()?;
        self.bytes -= raw.get().len();
        Some(raw)
    }

    fn push(&mut self, raw: Box<RawValue>) -> Result<(), ObserverError> {
        if self.events.len() >= MAXIMUM_PENDING_EVENTS
            || raw.get().len() > MAXIMUM_PENDING_BYTES.saturating_sub(self.bytes)
        {
            return Err(ObserverError::Protocol("timestamp_follow_buffer_limit"));
        }
        self.bytes += raw.get().len();
        self.events.push_back(raw);
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
enum Progress {
    Waiting,
    Continue,
    Done(u64),
}

struct TimestampOperation {
    id: String,
    value: Option<u64>,
}

impl TimestampOperation {
    fn started(result: Value) -> Result<Self, ObserverError> {
        if result.get("result").and_then(Value::as_str) != Some("started")
            || result.get("discardedItems").and_then(Value::as_u64) != Some(0)
        {
            return Err(ObserverError::Protocol("timestamp_storage_not_started"));
        }
        let id = result
            .get("operationId")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty() && id.len() <= 128)
            .ok_or(ObserverError::Protocol("timestamp_operation_id_invalid"))?;
        Ok(Self {
            id: id.to_owned(),
            value: None,
        })
    }

    fn accept(
        &mut self,
        raw: Box<RawValue>,
        pending: &mut PendingEvents,
    ) -> Result<Progress, ObserverError> {
        if raw.get().len() > MAXIMUM_PENDING_BYTES {
            return Err(ObserverError::Protocol("timestamp_follow_event_limit"));
        }
        let event: Value = serde_json::from_str(raw.get())?;
        let kind = event
            .get("event")
            .and_then(Value::as_str)
            .ok_or(ObserverError::Protocol("timestamp_follow_event_invalid"))?;
        if kind == "stop" {
            return Err(ObserverError::SubscriptionEnded);
        }
        if !kind.starts_with("operation") {
            pending.push(raw)?;
            return Ok(Progress::Waiting);
        }
        if event.get("operationId").and_then(Value::as_str) != Some(self.id.as_str()) {
            return Err(ObserverError::Protocol("timestamp_operation_id_mismatch"));
        }
        match kind {
            "operationStorageItems" => {
                let items = event
                    .get("items")
                    .and_then(Value::as_array)
                    .filter(|items| items.len() <= 1)
                    .ok_or(ObserverError::Protocol("timestamp_storage_items_invalid"))?;
                for item in items {
                    if item.get("key").and_then(Value::as_str) != Some(TIMESTAMP_NOW_KEY) {
                        return Err(ObserverError::Protocol("timestamp_storage_key_mismatch"));
                    }
                    let value =
                        decode_timestamp(item.get("value").cloned().unwrap_or(Value::Null))?;
                    if self.value.is_some_and(|prior| prior != value) {
                        return Err(ObserverError::Protocol("timestamp_storage_value_changed"));
                    }
                    self.value = Some(value);
                }
                Ok(Progress::Waiting)
            }
            "operationStorageDone" => self
                .value
                .map(Progress::Done)
                .ok_or(ObserverError::Protocol("missing_timestamp")),
            "operationWaitingForContinue" => Ok(Progress::Continue),
            "operationInaccessible" | "operationError" => {
                Err(ObserverError::TimestampStorageUnavailable)
            }
            _ => Err(ObserverError::Protocol(
                "unexpected_timestamp_operation_event",
            )),
        }
    }
}

fn retry_delay(error: &ObserverError, attempt: u32) -> Option<std::time::Duration> {
    match error {
        ObserverError::TimestampStorageUnavailable if attempt + 1 < TIMESTAMP_RPC_ATTEMPTS => {
            Some(TIMESTAMP_RETRY_DELAY * (1 << attempt))
        }
        _ => None,
    }
}

pub(crate) async fn timestamp_at(
    rpc: &LightClientRpc,
    subscription: &mut LightClientRpcSubscription,
    pending: &mut PendingEvents,
    hash: &str,
) -> Result<u64, ObserverError> {
    let subscription_id = subscription.id().to_owned();
    for attempt in 0..TIMESTAMP_RPC_ATTEMPTS {
        let result = rpc_with_deadline("chainHead_v1_storage", RPC_TIMEOUT, async {
            let started = rpc_value(
                rpc,
                "chainHead_v1_storage",
                serde_json::json!([
                    subscription_id, hash, [{"key": TIMESTAMP_NOW_KEY, "type": "value"}], null
                ]),
            )
            .await?;
            let mut operation = TimestampOperation::started(started)?;
            loop {
                let raw = subscription
                    .next()
                    .await
                    .ok_or(ObserverError::SubscriptionEnded)?
                    .map_err(|error| ObserverError::LightClient(error.to_string()))?;
                match operation.accept(raw, pending)? {
                    Progress::Waiting => {}
                    Progress::Done(value) => return Ok(value),
                    Progress::Continue => {
                        rpc_value(
                            rpc,
                            "chainHead_v1_continue",
                            serde_json::json!([subscription_id, operation.id]),
                        )
                        .await?;
                    }
                }
            }
        })
        .await;
        match result {
            Ok(value) => return Ok(value),
            Err(error) => {
                // A deadline or malformed event terminates this observer.
                // Only an explicit terminal storage error permits retry.
                let Some(delay) = retry_delay(&error, attempt) else {
                    return Err(error);
                };
                log::warn!(target: "umi-storage", "pinned timestamp operation failed; retrying");
                tokio::time::sleep(delay).await;
            }
        }
    }
    unreachable!("the final timestamp attempt always returns")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn raw(value: Value) -> Box<RawValue> {
        RawValue::from_string(value.to_string()).unwrap()
    }

    fn operation() -> TimestampOperation {
        TimestampOperation::started(
            json!({"result":"started", "operationId":"test", "discardedItems":0}),
        )
        .unwrap()
    }

    fn items(value: &str) -> Value {
        json!({"event":"operationStorageItems", "operationId":"test", "items":[{"key":TIMESTAMP_NOW_KEY,"value":value}]})
    }

    #[test]
    fn timestamp_requires_exact_operation_key_and_completed_result() {
        let mut op = operation();
        let mut pending = PendingEvents::default();
        assert_eq!(
            op.accept(raw(items("0x0100000000000000")), &mut pending)
                .unwrap(),
            Progress::Waiting
        );
        // The specification permits identical duplicates.
        assert_eq!(
            op.accept(raw(items("0x0100000000000000")), &mut pending)
                .unwrap(),
            Progress::Waiting
        );
        assert_eq!(
            op.accept(
                raw(json!({"event":"operationStorageDone","operationId":"test"})),
                &mut pending
            )
            .unwrap(),
            Progress::Done(1)
        );
        for bad in [
            json!({"event":"operationStorageDone","operationId":"other"}),
            json!({"event":"operationStorageItems","operationId":"test","items":[{"key":"0x00","value":"0x0100000000000000"}]}),
            items("0x01"),
            items("0x0200000000000000"),
            json!({"event":"operationStorageItems","operationId":"test","items":[{"key":TIMESTAMP_NOW_KEY,"value":null}]}),
        ] {
            assert!(op.accept(raw(bad), &mut pending).is_err());
        }
        assert!(
            operation()
                .accept(
                    raw(json!({"event":"operationStorageDone","operationId":"test"})),
                    &mut pending
                )
                .is_err()
        );
    }

    #[test]
    fn follow_notifications_survive_storage_query_in_order() {
        let mut pending = PendingEvents::default();
        let mut op = operation();
        for kind in ["newBlock", "bestBlockChanged", "finalized"] {
            assert_eq!(
                op.accept(raw(json!({"event":kind})), &mut pending).unwrap(),
                Progress::Waiting
            );
        }
        for kind in ["newBlock", "bestBlockChanged", "finalized"] {
            assert_eq!(
                serde_json::from_str::<Value>(pending.pop().unwrap().get()).unwrap()["event"],
                kind
            );
        }
        assert!(pending.pop().is_none());
        assert_eq!(pending.bytes, 0);
    }

    #[test]
    fn errors_stop_events_and_backpressure_are_explicit() {
        let mut op = operation();
        let mut pending = PendingEvents::default();
        assert_eq!(
            op.accept(
                raw(json!({"event":"operationWaitingForContinue","operationId":"test"})),
                &mut pending
            )
            .unwrap(),
            Progress::Continue
        );
        assert!(matches!(
            op.accept(raw(json!({"event":"stop"})), &mut pending),
            Err(ObserverError::SubscriptionEnded)
        ));
        for kind in ["operationInaccessible", "operationError"] {
            assert!(matches!(
                op.accept(
                    raw(json!({"event":kind,"operationId":"test"})),
                    &mut pending
                ),
                Err(ObserverError::TimestampStorageUnavailable)
            ));
        }
        for result in [
            json!({"result":"limitReached"}),
            json!({"result":"started","operationId":"test","discardedItems":1}),
        ] {
            assert!(TimestampOperation::started(result).is_err());
        }
    }

    #[test]
    fn pending_notifications_have_count_and_byte_limits() {
        let mut pending = PendingEvents::default();
        for _ in 0..MAXIMUM_PENDING_EVENTS {
            pending.push(raw(json!({"event":"newBlock"}))).unwrap();
        }
        assert!(pending.push(raw(json!({"event":"newBlock"}))).is_err());
        assert!(
            PendingEvents::default()
                .push(raw(json!("x".repeat(MAXIMUM_PENDING_BYTES))))
                .is_err()
        );
    }

    #[test]
    fn only_terminal_storage_errors_permit_bounded_retries() {
        assert_eq!(
            retry_delay(&ObserverError::TimestampStorageUnavailable, 0),
            Some(TIMESTAMP_RETRY_DELAY)
        );
        assert_eq!(
            retry_delay(&ObserverError::TimestampStorageUnavailable, 1),
            Some(TIMESTAMP_RETRY_DELAY * 2)
        );
        assert_eq!(
            retry_delay(&ObserverError::TimestampStorageUnavailable, 2),
            None
        );
        for error in [
            ObserverError::RpcTimeout("chainHead_v1_storage"),
            ObserverError::LightClient("unknown operation outcome".to_owned()),
            ObserverError::Protocol("invalid_timestamp"),
            ObserverError::SubscriptionEnded,
        ] {
            assert_eq!(retry_delay(&error, 0), None);
        }
    }
}
