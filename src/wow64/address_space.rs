//! WoW64 low-address-space reservation helpers.

use std::sync::OnceLock;

/// 4 GiB boundary used by 32-bit pointers.
pub const LOW_4GB_LIMIT: usize = 0x1_0000_0000;

/// Keep first page invalid to preserve null pointer semantics.
pub const WOW64_LOW_START: usize = 0x1_0000;

/// A logical reservation of the address range available to WoW64 mappings.
///
/// The runtime uses this to validate that mapped images remain within the
/// 32-bit pointerable range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LowAddressReservation {
    pub start: usize,
    pub end: usize,
}

impl LowAddressReservation {
    pub fn size(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    pub fn contains_addr(&self, addr: usize) -> bool {
        addr >= self.start && addr < self.end
    }

    pub fn contains_range(&self, base: usize, size: usize) -> bool {
        if size == 0 {
            return self.contains_addr(base);
        }

        let Some(end) = base.checked_add(size) else {
            return false;
        };

        base >= self.start && end <= self.end
    }
}

fn global_reservation() -> &'static OnceLock<LowAddressReservation> {
    static RESERVATION: OnceLock<LowAddressReservation> = OnceLock::new();
    &RESERVATION
}

/// Reserve the logical low 4 GiB address space for WoW64 usage.
pub fn reserve_low_4gb_on_startup() -> &'static LowAddressReservation {
    global_reservation()
        .get_or_init(|| LowAddressReservation { start: WOW64_LOW_START, end: LOW_4GB_LIMIT })
}

/// Return true when the address is representable in 32-bit space.
pub fn is_low_4gb_address(addr: usize) -> bool {
    reserve_low_4gb_on_startup().contains_addr(addr)
}

/// Validate an image mapping lies entirely inside the reserved WoW64 range.
pub fn validate_low_4gb_mapping(base: usize, size: usize) -> Result<(), String> {
    let reservation = reserve_low_4gb_on_startup();
    if reservation.contains_range(base, size) {
        Ok(())
    } else {
        Err(format!(
            "mapping [0x{base:x}, 0x{:x}) is outside WoW64 low address space",
            base.saturating_add(size)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservation_is_stable_and_non_empty() {
        let res = reserve_low_4gb_on_startup();
        assert_eq!(res.start, WOW64_LOW_START);
        assert_eq!(res.end, LOW_4GB_LIMIT);
        assert!(res.size() > 0);
    }

    #[test]
    fn low_address_checks_work() {
        assert!(is_low_4gb_address(0x1234_5678));
        assert!(!is_low_4gb_address(0x1_0000_0000));
    }

    #[test]
    fn mapping_validation_rejects_high_ranges() {
        let ok = validate_low_4gb_mapping(0x0040_0000, 0x2000);
        assert!(ok.is_ok());

        let err = validate_low_4gb_mapping(0x1_0000_0000, 0x1000);
        assert!(err.is_err());
    }
}
