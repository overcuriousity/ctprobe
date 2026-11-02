//! Rates over a sliding time window, so bursts of work do not read as swings.

use std::collections::VecDeque;

/// Samples of a growing counter from the last `secs` seconds.
pub struct RateWindow {
    span_ms: i64,
    samples: VecDeque<(i64, u64)>,
}

impl RateWindow {
    pub fn new(secs: u32) -> RateWindow {
        RateWindow { span_ms: secs as i64 * 1000, samples: VecDeque::new() }
    }

    pub fn push(&mut self, t_ms: i64, value: u64) {
        self.samples.push_back((t_ms, value));
        while self.samples.front().is_some_and(|(t, _)| t_ms - t > self.span_ms) {
            self.samples.pop_front();
        }
    }

    /// Change per second across the samples held, so a young window is usable.
    pub fn rate(&self) -> f64 {
        let (Some(first), Some(last)) = (self.samples.front(), self.samples.back()) else {
            return 0.0;
        };
        if last.0 <= first.0 {
            return 0.0;
        }
        last.1.saturating_sub(first.1) as f64 * 1000.0 / (last.0 - first.0) as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_uses_available_time_in_first_minute() {
        let mut w = RateWindow::new(60);
        w.push(0, 0);
        w.push(10_000, 500);
        assert_eq!(w.rate(), 50.0);
    }

    #[test]
    fn old_samples_leave_the_window() {
        let mut w = RateWindow::new(60);
        w.push(0, 0);
        w.push(1_000, 10_000);
        for s in 2..=62 {
            w.push(s * 1000, 10_000 + (s as u64 - 1) * 10);
        }
        assert!((w.rate() - 10.0).abs() < 0.5);
    }

    #[test]
    fn single_sample_is_zero() {
        let mut w = RateWindow::new(60);
        w.push(0, 5);
        assert_eq!(w.rate(), 0.0);
    }
}
