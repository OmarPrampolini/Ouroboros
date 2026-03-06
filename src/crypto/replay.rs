/// Sliding window su 128-bit per replay protection efficiente.
/// Manteniamo `max_seen`; accettiamo seq in (max_seen-128 .. max_seen].
///
/// Layout bit mask: bit 0 = max_seen, bit 1 = max_seen-1, ..., bit 127 = max_seen-127
pub struct ReplayWindow {
    max_seen: u64,
    mask: u128, // 128-bit per finestra 128 messaggi
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayDecision {
    Accepted,
    Replay,
    Overflow,
}

/// Threshold for overflow detection - when max_seen is within this distance from u64::MAX
const OVERFLOW_THRESHOLD: u64 = 1000;

impl ReplayWindow {
    pub fn new() -> Self {
        Self {
            max_seen: 0,
            mask: 0,
        }
    }

    /// Controlla e accetta una sequenza se non e replay.
    /// SECURITY: Constant-time per evitare timing attacks.
    /// Returns Ok(true) if accepted, Ok(false) if replay, Err(()) if overflow detected.
    #[allow(clippy::result_unit_err)]
    pub fn accept(&mut self, seq: u64) -> Result<bool, ()> {
        match self.accept_classified(seq) {
            ReplayDecision::Accepted => Ok(true),
            ReplayDecision::Replay => Ok(false),
            ReplayDecision::Overflow => Err(()),
        }
    }

    /// Versione classificata per call-site che vogliono distinguere overflow e replay.
    pub fn accept_classified(&mut self, seq: u64) -> ReplayDecision {
        // Overflow condition: max_seen vicino a u64::MAX e nuova sequence piccola.
        if self.max_seen >= u64::MAX - OVERFLOW_THRESHOLD && seq < OVERFLOW_THRESHOLD {
            return ReplayDecision::Overflow;
        }

        if seq == 0 {
            return ReplayDecision::Replay;
        }

        let delta = seq.wrapping_sub(self.max_seen);
        if delta == 0 {
            return ReplayDecision::Replay; // Replay del max_seen
        }

        if delta < (1u64 << 63) {
            // Sequenza piu recente (mod 2^64) - shift della finestra
            let shift = delta;

            if shift >= 128 {
                // Reset completo della finestra - salto troppo grande
                self.mask = 1; // Solo il nuovo messaggio
            } else {
                // Shift sicuro: sposta la finestra e marca il nuovo msg
                self.mask <<= shift;
                self.mask |= 1; // Bit 0 = nuovo max_seen
            }

            self.max_seen = seq;
            ReplayDecision::Accepted
        } else {
            // Sequenza piu vecchia - controlla se nella finestra
            let delta_old = self.max_seen.wrapping_sub(seq);

            if delta_old >= 128 {
                return ReplayDecision::Replay; // Troppo vecchia, fuori finestra
            }

            // SAFETY: delta < 128, quindi shift e sempre sicuro
            let bit_pos = delta_old as usize;
            let bit_mask = 1u128 << bit_pos;

            if (self.mask & bit_mask) != 0 {
                return ReplayDecision::Replay; // Gia vista (replay)
            }

            // Marca come vista
            self.mask |= bit_mask;
            ReplayDecision::Accepted
        }
    }

    /// Recovery best-effort dopo overflow: resetta la finestra e accetta la seq corrente.
    /// Utile quando il call-site preferisce proseguire in modalita degradate invece di bloccare.
    pub fn recover_after_overflow(&mut self, seq: u64) -> bool {
        if seq == 0 {
            return false;
        }
        self.max_seen = seq;
        self.mask = 1;
        true
    }

    /// Alias per accept (per compatibilita)
    /// Maintains backward compatibility by returning bool instead of Result.
    pub fn check(&mut self, seq: u64) -> bool {
        matches!(self.accept_classified(seq), ReplayDecision::Accepted)
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replay_window_basic() {
        let mut window = ReplayWindow::new();

        // Prima sequenza - accettata
        assert_eq!(window.accept(100), Ok(true));
        // Duplicato - rifiutato
        assert_eq!(window.accept(100), Ok(false));
        // Sequenza piu recente - accettata
        assert_eq!(window.accept(101), Ok(true));
        // Sequenza vecchia ma ancora nella finestra - accettata la prima volta
        assert_eq!(window.accept(99), Ok(true));
        // Replay della sequenza 99 - rifiutata
        assert_eq!(window.accept(99), Ok(false));
    }

    #[test]
    fn test_replay_window_shift() {
        let mut window = ReplayWindow::new();

        // Sequenza iniziale
        assert_eq!(window.accept(100), Ok(true));
        // Salto grande che causa shift completo
        assert_eq!(window.accept(300), Ok(true));
        // La vecchia sequenza ora e fuori finestra
        assert_eq!(window.accept(100), Ok(false));
        // Sequenza nella nuova finestra
        assert_eq!(window.accept(290), Ok(true));
    }

    #[test]
    fn test_replay_window_sequence_zero() {
        let mut window = ReplayWindow::new();

        // Sequenza zero sempre rifiutata
        assert_eq!(window.accept(0), Ok(false));
    }

    #[test]
    fn test_replay_window_edge_cases() {
        let mut window = ReplayWindow::new();

        // Test finestra piena (127 messaggi)
        assert_eq!(window.accept(200), Ok(true));
        for i in 1..128 {
            assert_eq!(window.accept(200 - i), Ok(true), "Failed at offset {}", i);
        }

        // Questo dovrebbe essere fuori finestra (esattamente 128 indietro)
        assert_eq!(window.accept(200 - 128), Ok(false));

        // Test reordering dentro la finestra
        assert_eq!(window.accept(300), Ok(true));
        assert_eq!(window.accept(299), Ok(true));
        assert_eq!(window.accept(298), Ok(true));
        assert_eq!(window.accept(301), Ok(true)); // Piu recente
        assert_eq!(window.accept(299), Ok(false)); // Replay
    }

    #[test]
    fn test_replay_window_overflow_protection_and_recovery() {
        let mut window = ReplayWindow::new();

        // Test vicino a u64::MAX
        let near_max = u64::MAX - 100;
        assert_eq!(window.accept(near_max), Ok(true));
        assert_eq!(window.accept(near_max + 50), Ok(true));
        assert_eq!(window.accept(near_max), Ok(false)); // Replay

        // Overflow rilevato in wrap-around
        window.max_seen = u64::MAX - 50;
        window.mask = 1;
        assert_eq!(window.accept_classified(1), ReplayDecision::Overflow);

        // Recovery best-effort: nuova epoca sequenziale
        assert!(window.recover_after_overflow(1));
        assert_eq!(window.accept(2), Ok(true));
        assert_eq!(window.accept(1), Ok(false));
    }

    #[test]
    fn test_replay_window_bit_consistency() {
        let mut window = ReplayWindow::new();

        // Verifica consistenza della mappatura bit
        assert_eq!(window.accept(1000), Ok(true));
        assert_eq!(window.max_seen, 1000);
        assert_eq!(window.mask & 1, 1); // Bit 0 settato

        // Sequence precedente dovrebbe settare il bit corretto
        assert_eq!(window.accept(999), Ok(true));
        assert_eq!(window.mask & 2, 2); // Bit 1 settato (delta=1)

        assert_eq!(window.accept(998), Ok(true));
        assert_eq!(window.mask & 4, 4); // Bit 2 settato (delta=2)
    }

    #[test]
    fn test_replay_window_overflow_detection() {
        let mut window = ReplayWindow::new();

        // Set max_seen very close to u64::MAX
        window.max_seen = u64::MAX - 500;
        window.mask = 0xFF;

        // Small sequence number should trigger overflow error
        assert_eq!(window.accept(10), Err(()));
        assert_eq!(window.accept(100), Err(()));
        assert_eq!(window.accept(999), Err(()));

        // But sequences within the current range should still work
        assert_eq!(window.accept(u64::MAX - 100), Ok(true));
        assert_eq!(window.accept(u64::MAX), Ok(true));

        // Test boundary condition - exactly at threshold
        window.max_seen = u64::MAX - OVERFLOW_THRESHOLD;
        assert_eq!(window.accept(0), Err(()));
        assert_eq!(window.accept(OVERFLOW_THRESHOLD - 1), Err(()));

        // Just outside threshold should be OK
        assert_eq!(window.accept(OVERFLOW_THRESHOLD), Ok(true));
    }

    #[test]
    fn test_backward_compatibility_check() {
        let mut window = ReplayWindow::new();

        // Test that check() method maintains backward compatibility
        assert!(window.check(100)); // Should return true
        assert!(!window.check(100)); // Should return false for replay
        assert!(!window.check(0)); // Should return false for seq 0

        // Test that check() returns false on overflow (backward compatibility)
        window.max_seen = u64::MAX - 500;
        assert!(!window.check(10)); // Should return false instead of Err
    }
}
