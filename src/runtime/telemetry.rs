//! Lightweight runtime breadcrumbs for crash triage.

use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};

const MAX_EVENTS: usize = 256;

fn events() -> &'static Mutex<VecDeque<String>> {
    static EVENTS: OnceLock<Mutex<VecDeque<String>>> = OnceLock::new();
    EVENTS.get_or_init(|| Mutex::new(VecDeque::with_capacity(MAX_EVENTS)))
}

pub fn record(event: impl Into<String>) {
    let mut guard = events().lock().expect("runtime telemetry queue poisoned");
    if guard.len() >= MAX_EVENTS {
        let _ = guard.pop_front();
    }
    guard.push_back(event.into());
}

pub fn recent(limit: usize) -> Vec<String> {
    let guard = events().lock().expect("runtime telemetry queue poisoned");
    let take = limit.min(guard.len());
    guard.iter().rev().take(take).cloned().collect::<Vec<_>>().into_iter().rev().collect()
}

pub fn recent_compact(limit: usize) -> String {
    let items = recent(limit);
    if items.is_empty() {
        return "<no breadcrumbs>".to_string();
    }
    items.join(" | ")
}
