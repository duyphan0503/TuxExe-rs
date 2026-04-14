//! 32→64 bit thunking — convert 32-bit API parameters for 64-bit internal handlers.

use std::collections::BTreeMap;

/// Signature-level description for each 32-bit argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThunkArgKind {
    U32,
    I32,
    Bool,
    Pointer,
    Handle,
}

/// A normalized argument value passed to 64-bit handlers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThunkArgValue {
    U64(u64),
    I64(i64),
    Bool(bool),
    Pointer(usize),
    Handle(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThunkCallSpec {
    pub api_name: String,
    pub signature: Vec<ThunkArgKind>,
}

impl ThunkCallSpec {
    pub fn new(api_name: impl Into<String>, signature: &[ThunkArgKind]) -> Self {
        Self { api_name: api_name.into(), signature: signature.to_vec() }
    }
}

#[derive(Debug, Default, Clone)]
pub struct ThunkDispatcher {
    registry: BTreeMap<String, ThunkCallSpec>,
}

impl ThunkDispatcher {
    pub fn register(&mut self, api_name: impl Into<String>, signature: &[ThunkArgKind]) {
        let api_name = api_name.into();
        let key = api_name.to_ascii_lowercase();
        self.registry.insert(key, ThunkCallSpec::new(api_name, signature));
    }

    pub fn normalize_call(
        &self,
        api_name: &str,
        args32: &[u32],
    ) -> Result<Vec<ThunkArgValue>, String> {
        let key = api_name.to_ascii_lowercase();
        let spec = self
            .registry
            .get(&key)
            .ok_or_else(|| format!("missing thunk signature for {api_name}"))?;
        thunk_call_frame(args32, &spec.signature)
    }

    pub fn known_api_count(&self) -> usize {
        self.registry.len()
    }
}

/// Convert one 32-bit argument to a widened internal value.
pub fn widen_arg(raw: u32, kind: ThunkArgKind) -> ThunkArgValue {
    match kind {
        ThunkArgKind::U32 => ThunkArgValue::U64(raw as u64),
        ThunkArgKind::I32 => ThunkArgValue::I64((raw as i32) as i64),
        ThunkArgKind::Bool => ThunkArgValue::Bool(raw != 0),
        ThunkArgKind::Pointer => ThunkArgValue::Pointer(raw as usize),
        ThunkArgKind::Handle => ThunkArgValue::Handle(raw as usize),
    }
}

/// Convert a 32-bit call frame into widened arguments.
pub fn thunk_call_frame(
    args32: &[u32],
    signature: &[ThunkArgKind],
) -> Result<Vec<ThunkArgValue>, String> {
    if args32.len() < signature.len() {
        return Err(format!("thunk expected {} args but got {}", signature.len(), args32.len()));
    }

    Ok(signature.iter().zip(args32.iter()).map(|(&kind, &raw)| widen_arg(raw, kind)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn widens_pointer_and_handle_without_sign_extension() {
        assert_eq!(
            widen_arg(0xFFFF_FF00, ThunkArgKind::Pointer),
            ThunkArgValue::Pointer(0xFFFF_FF00)
        );
        assert_eq!(
            widen_arg(0x8000_0001, ThunkArgKind::Handle),
            ThunkArgValue::Handle(0x8000_0001)
        );
    }

    #[test]
    fn widens_signed_values_with_sign_extension() {
        assert_eq!(widen_arg(0xFFFF_FFFF, ThunkArgKind::I32), ThunkArgValue::I64(-1));
        assert_eq!(widen_arg(0x8000_0000, ThunkArgKind::I32), ThunkArgValue::I64(i32::MIN as i64));
    }

    #[test]
    fn converts_complete_call_frame() {
        let signature =
            [ThunkArgKind::Handle, ThunkArgKind::Pointer, ThunkArgKind::U32, ThunkArgKind::Bool];
        let args32 = [0x1234, 0x4000_2000, 77, 1];
        let thunked = thunk_call_frame(&args32, &signature).expect("thunk should succeed");

        assert_eq!(
            thunked,
            vec![
                ThunkArgValue::Handle(0x1234),
                ThunkArgValue::Pointer(0x4000_2000),
                ThunkArgValue::U64(77),
                ThunkArgValue::Bool(true),
            ]
        );
    }

    #[test]
    fn dispatcher_normalizes_registered_calls() {
        let mut dispatcher = ThunkDispatcher::default();
        dispatcher.register(
            "CreateFileW",
            &[
                ThunkArgKind::Pointer,
                ThunkArgKind::U32,
                ThunkArgKind::U32,
                ThunkArgKind::Pointer,
                ThunkArgKind::U32,
                ThunkArgKind::U32,
                ThunkArgKind::Handle,
            ],
        );

        let values = dispatcher
            .normalize_call("createfilew", &[0x1000, 1, 2, 0, 3, 4, 0xFFFF_FF01])
            .expect("registered call should normalize");
        assert_eq!(values.len(), 7);
        assert_eq!(values[0], ThunkArgValue::Pointer(0x1000));
        assert_eq!(values[6], ThunkArgValue::Handle(0xFFFF_FF01));
    }

    #[test]
    fn dispatcher_rejects_unknown_api() {
        let dispatcher = ThunkDispatcher::default();
        let err = dispatcher.normalize_call("UnknownApi", &[]).expect_err("unknown API must fail");
        assert!(err.contains("missing thunk signature"));
    }
}
