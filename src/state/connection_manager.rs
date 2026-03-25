use crate::config::CONNECTION_BASE_TIMEOUT_SECS;
use serde::{Deserialize, Serialize};
/// Auto-Reconnection with Circuit Breaker e State Machine
/// Zero-persistence: tutto in RAM, niente log di tentativi
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tracing::{error, info, warn};

use crate::{
    config::Config,
    derive::RendezvousParams,
    transport::{self, Connection},
};
use ethersync::EtherNode;
use std::sync::Arc;

/// Circuit Breaker states per resilienza rete
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum CircuitState {
    Closed,   // Normal operation
    Open,     // Failing, não tenta conexões
    HalfOpen, // Testing recovery
}

/// Connection State Machine (esplicita per evitare race conditions)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ConnectionFsmState {
    Idle,
    Resolving,
    Connecting,
    Secured,
    Draining,
    Closed,
    Error(String),
}

/// Circuit Breaker con exponential backoff
#[derive(Clone)]
pub struct ConnectionCircuitBreaker {
    state: CircuitState,
    failure_count: u32,
    last_failure: Option<Instant>,
    success_count: u32,

    // Configuration
    failure_threshold: u32, // Failures before opening circuit
    success_threshold: u32, // Successes to close circuit from half-open
    base_timeout: Duration, // Base timeout for open state
    max_timeout: Duration,  // Cap exponential backoff
}

impl ConnectionCircuitBreaker {
    pub fn new(cfg: &Config) -> Self {
        Self {
            state: CircuitState::Closed,
            failure_count: 0,
            last_failure: None,
            success_count: 0,
            failure_threshold: cfg.circuit_breaker_failure_threshold,
            success_threshold: cfg.circuit_breaker_success_threshold,
            base_timeout: Duration::from_secs(CONNECTION_BASE_TIMEOUT_SECS), // 5s base timeout
            max_timeout: Duration::from_secs(300),                           // Max 5min timeout
        }
    }

    /// Check if we can attempt a connection
    pub fn can_attempt(&self) -> bool {
        match self.state {
            CircuitState::Closed => true,
            CircuitState::HalfOpen => true,
            CircuitState::Open => {
                if let Some(last_failure) = self.last_failure {
                    let timeout = self.calculate_backoff();
                    last_failure.elapsed() >= timeout
                } else {
                    true // No recorded failure, allow attempt
                }
            }
        }
    }

    /// Record successful connection
    pub fn record_success(&mut self) {
        match self.state {
            CircuitState::Closed => {
                self.failure_count = 0; // Reset failure count
            }
            CircuitState::HalfOpen => {
                self.success_count += 1;
                if self.success_count >= self.success_threshold {
                    info!("Circuit breaker closing - connection restored");
                    self.state = CircuitState::Closed;
                    self.failure_count = 0;
                    self.success_count = 0;
                    self.last_failure = None;
                }
            }
            CircuitState::Open => {
                // Transition to half-open on first success from open
                warn!("Circuit breaker transitioning to half-open");
                self.state = CircuitState::HalfOpen;
                self.success_count = 1;
            }
        }
    }

    /// Record connection failure
    pub fn record_failure(&mut self) {
        self.failure_count += 1;
        self.last_failure = Some(Instant::now());
        self.success_count = 0; // Reset success count

        match self.state {
            CircuitState::Closed => {
                if self.failure_count >= self.failure_threshold {
                    warn!(
                        "Circuit breaker opening after {} failures",
                        self.failure_count
                    );
                    self.state = CircuitState::Open;
                }
            }
            CircuitState::HalfOpen => {
                warn!("Circuit breaker reopening - connection still failing");
                self.state = CircuitState::Open;
            }
            CircuitState::Open => {
                // Already open, just update failure time for backoff
            }
        }
    }

    /// Get current circuit breaker status
    pub fn get_status(&self) -> CircuitBreakerStatus {
        CircuitBreakerStatus {
            state: self.state,
            failure_count: self.failure_count,
            success_count: self.success_count,
            next_attempt_in: if self.state == CircuitState::Open {
                self.last_failure.map(|last| {
                    let timeout = self.calculate_backoff();
                    timeout.saturating_sub(last.elapsed())
                })
            } else {
                None
            },
        }
    }

    /// Calculate exponential backoff timeout
    fn calculate_backoff(&self) -> Duration {
        let multiplier: u32 = 2_u32.pow((self.failure_count - 1).min(8));
        let timeout = self
            .base_timeout
            .checked_mul(multiplier)
            .unwrap_or(self.max_timeout);
        timeout.min(self.max_timeout)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerStatus {
    pub state: CircuitState,
    pub failure_count: u32,
    pub success_count: u32,
    pub next_attempt_in: Option<Duration>,
}

/// Connection Manager with Auto-Reconnect
pub struct ConnectionManager {
    circuit_breaker: ConnectionCircuitBreaker,
    fsm_state: ConnectionFsmState,
    connection: Option<Connection>,
    params: Option<RendezvousParams>,
    reconnect_task: Option<tokio::task::JoinHandle<()>>,
}

impl ConnectionManager {
    pub fn new() -> Self {
        let cfg = Config::from_env();
        Self {
            circuit_breaker: ConnectionCircuitBreaker::new(&cfg),
            fsm_state: ConnectionFsmState::Idle,
            connection: None,
            params: None,
            reconnect_task: None,
        }
    }

    /// Attempt to establish connection with circuit breaker protection.
    ///
    /// When `orp_node` is `Some`, ORP route discovery is tried between
    /// Relay and Tor in the transport fallback chain.
    pub async fn connect(
        &mut self,
        params: RendezvousParams,
        orp_node: Option<Arc<EtherNode>>,
    ) -> Result<Connection, anyhow::Error> {
        if !self.circuit_breaker.can_attempt() {
            let status = self.circuit_breaker.get_status();
            return Err(anyhow::anyhow!(
                "Circuit breaker {:?}, next attempt in {:?}",
                status.state,
                status.next_attempt_in
            ));
        }

        self.fsm_state = ConnectionFsmState::Connecting;
        self.params = Some(params.clone());

        let cfg = Config::from_env();
        match transport::establish_connection_with_orp(
            &params,
            &cfg,
            orp_node.as_deref(),
        )
        .await
        {
            Ok(conn) => {
                info!("Connection established successfully");
                self.circuit_breaker.record_success();
                self.fsm_state = ConnectionFsmState::Secured;
                self.connection = Some(conn.clone());
                Ok(conn)
            }
            Err(e) => {
                error!("Connection failed: {}", e);
                self.circuit_breaker.record_failure();
                self.fsm_state = ConnectionFsmState::Error(e.to_string());
                Err(anyhow::anyhow!("{}", e))
            }
        }
    }

    /// Start auto-reconnect task (non-blocking)
    pub fn start_auto_reconnect(&mut self) -> tokio::sync::watch::Receiver<Option<Connection>> {
        let (tx, rx) = tokio::sync::watch::channel(None);
        let params = self.params.clone();

        if let Some(params) = params {
            let mut circuit_breaker = self.circuit_breaker.clone();

            let task = tokio::spawn(async move {
                loop {
                    if !circuit_breaker.can_attempt() {
                        let status = circuit_breaker.get_status();
                        if let Some(wait_time) = status.next_attempt_in {
                            info!(
                                "Auto-reconnect waiting {:?} due to circuit breaker",
                                wait_time
                            );
                            sleep(wait_time).await;
                        }
                        continue;
                    }

                    info!("Auto-reconnect attempting...");
                    let cfg = Config::from_env();
                    match transport::establish_connection(&params, &cfg).await {
                        Ok(conn) => {
                            info!("Auto-reconnect successful");
                            circuit_breaker.record_success();

                            // Send new connection
                            if tx.send(Some(conn)).is_err() {
                                info!("Auto-reconnect task stopping - receiver dropped");
                                break;
                            }

                            // Wait longer on success (connection stability check)
                            sleep(Duration::from_secs(30)).await;
                        }
                        Err(e) => {
                            warn!("Auto-reconnect failed: {}", e);
                            circuit_breaker.record_failure();

                            // Send connection lost signal
                            let _ = tx.send(None);

                            // Wait with exponential backoff
                            let backoff = circuit_breaker.calculate_backoff();
                            sleep(backoff).await;
                        }
                    }
                }
            });

            self.reconnect_task = Some(task);
        }

        rx
    }

    /// Stop auto-reconnect
    pub fn stop_auto_reconnect(&mut self) {
        if let Some(task) = self.reconnect_task.take() {
            task.abort();
        }
    }

    /// Get current FSM state
    pub fn get_state(&self) -> &ConnectionFsmState {
        &self.fsm_state
    }

    /// Get circuit breaker status  
    pub fn get_circuit_status(&self) -> CircuitBreakerStatus {
        self.circuit_breaker.get_status()
    }

    /// Force circuit breaker to closed state (manual recovery)
    pub fn reset_circuit_breaker(&mut self) {
        info!("Manually resetting circuit breaker");
        let cfg = Config::from_env();
        self.circuit_breaker = ConnectionCircuitBreaker::new(&cfg);
        self.fsm_state = ConnectionFsmState::Idle;
    }
}

impl Default for ConnectionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ConnectionManager {
    fn drop(&mut self) {
        self.stop_auto_reconnect();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_breaker_basic() {
        let cfg = Config::from_env();
        let mut cb = ConnectionCircuitBreaker::new(&cfg);

        assert!(cb.can_attempt());
        assert_eq!(cb.get_status().state, CircuitState::Closed);

        // Record failures to open circuit
        cb.record_failure();
        cb.record_failure();
        cb.record_failure(); // Should open circuit

        assert_eq!(cb.get_status().state, CircuitState::Open);
    }

    #[test]
    fn test_exponential_backoff() {
        let cfg = Config::from_env();
        let mut cb = ConnectionCircuitBreaker::new(&cfg);

        cb.record_failure();
        let first_timeout = cb.calculate_backoff();

        cb.record_failure();
        let second_timeout = cb.calculate_backoff();

        assert!(second_timeout > first_timeout);
    }

    #[tokio::test]
    async fn test_connection_manager() {
        let manager = ConnectionManager::new();

        assert_eq!(*manager.get_state(), ConnectionFsmState::Idle);
        assert!(manager.get_circuit_status().state == CircuitState::Closed);
    }
}
