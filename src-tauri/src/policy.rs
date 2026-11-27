//! Scan pause policy driven by device state (network, VPN, battery, overheating, Android
//! limits).
//!
//! Pure logic without dependencies (testable on desktop:
//! `rustc --edition 2021 --test src-tauri/src/policy.rs`). The bridge (`bridge.rs`) feeds it
//! Kotlin monitor events and user actions and carries out its decisions:
//! `engine.pause(reason)` / `engine.resume()` / `scan_stop { reason }`.
//!
//! There is one rule: the scan is paused if the user or the environment wants it paused.
//! Clearing an environment reason resumes the scan only if the user did not pause it; the
//! user's resume does not lift the pause while an environment reason holds (except
//! `android`).

/// Default network transport (ConnectivityManager).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    None,
    Wifi,
    Cellular,
    Ethernet,
    Other,
}

impl Transport {
    pub fn parse(s: &str) -> Transport {
        match s {
            "wifi" => Transport::Wifi,
            "cellular" => Transport::Cellular,
            "ethernet" => Transport::Ethernet,
            "none" | "" => Transport::None,
            _ => Transport::Other,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::None => "none",
            Transport::Wifi => "wifi",
            Transport::Cellular => "cellular",
            Transport::Ethernet => "ethernet",
            Transport::Other => "other",
        }
    }
}

/// Device state. Defaults to "all good" (desktop, or before the first monitor event).
#[derive(Debug, Clone, PartialEq)]
pub struct Env {
    pub online: bool,
    pub transport: Transport,
    pub vpn: bool,
    pub metered: bool,
    /// Battery level in percent; `None` if unknown.
    pub battery: Option<u8>,
    pub charging: bool,
    /// PowerManager.THERMAL_STATUS_*: 0 none … 3 SEVERE … 6 SHUTDOWN.
    pub thermal: u8,
    /// This month's mobile traffic has reached `power.mob_limit` (the engine's counter).
    pub mobile_cap: bool,
}

impl Env {
    /// The device is on a mobile or metered network (traffic counts against the monthly limit).
    pub fn on_mobile(&self) -> bool {
        self.online && (self.transport == Transport::Cellular || self.metered)
    }
}

impl Default for Env {
    fn default() -> Self {
        Env {
            online: true,
            transport: Transport::Other,
            vpn: false,
            metered: false,
            battery: None,
            charging: false,
            thermal: 0,
            mobile_cap: false,
        }
    }
}

/// Settings from `Settings.power` and `Settings.net` (docs/API.md).
#[derive(Debug, Clone, PartialEq)]
pub struct PolicySettings {
    pub wifi_only: bool,
    pub batt_on: bool,
    pub batt: u8,
    /// `batt_action == "stop"` (the UI default is pause).
    pub batt_stop: bool,
    pub charge_only: bool,
    pub heat: bool,
    pub kill_switch: bool,
    /// `kill_action != "pause"`: stop (active mode always stops).
    pub kill_stop: bool,
}

impl Default for PolicySettings {
    fn default() -> Self {
        PolicySettings {
            wifi_only: false,
            batt_on: false,
            batt: 15,
            batt_stop: false,
            charge_only: false,
            heat: false,
            kill_switch: false,
            kill_stop: true,
        }
    }
}

/// What to do with the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Pause(&'static str),
    Resume,
    Stop(&'static str),
}

/// Overheating threshold: THERMAL_STATUS_SEVERE.
pub const THERMAL_SEVERE: u8 = 3;

#[derive(Debug, Default)]
pub struct Policy {
    scanning: bool,
    active: bool,
    /// The tunnel was up during the scan, so losing it counts as a drop (kill switch).
    vpn_seen: bool,
    user_paused: bool,
    env_reason: Option<&'static str>,
}

impl Policy {
    pub fn new() -> Self {
        Self::default()
    }

    #[allow(dead_code)]
    pub fn scanning(&self) -> bool {
        self.scanning
    }

    /// Returns the current environment pause reason
    /// (`offline`/`vpn`/`battery`/`thermal`/`wifi`/`mobile_cap`/`android`).
    pub fn env_reason(&self) -> Option<&'static str> {
        self.env_reason
    }

    pub fn user_paused(&self) -> bool {
        self.user_paused
    }

    /// Returns what the environment demands as `(reason, stop?)`. Priority: network > tunnel >
    /// battery > overheating > Wi-Fi > monthly mobile data limit.
    pub fn demand(&self, env: &Env, s: &PolicySettings) -> Option<(&'static str, bool)> {
        if !env.online || env.transport == Transport::None {
            return Some(("offline", false));
        }
        if s.kill_switch && self.vpn_seen && !env.vpn {
            return Some(("vpn", self.active || s.kill_stop));
        }
        if let Some(level) = env.battery {
            if s.batt_on && !env.charging && level < s.batt {
                return Some(("battery", s.batt_stop));
            }
        }
        if s.charge_only && env.battery.is_some() && !env.charging {
            return Some(("battery", false));
        }
        // The UI has no separate overheating reason here; it is shown as power.
        if s.heat && env.thermal >= THERMAL_SEVERE {
            // Overheating is its own reason (the UI shows a dedicated message), not "power".
            return Some(("thermal", false));
        }
        if s.wifi_only && env.transport == Transport::Cellular {
            return Some(("wifi", false));
        }
        // The monthly limit only holds on mobile data: Wi-Fi lifts it, so does a raised limit.
        if env.mobile_cap && env.on_mobile() {
            return Some(("mobile_cap", false));
        }
        None
    }

    /// Handles scan start (the `started` event).
    pub fn scan_started(&mut self, active: bool, env: &Env, s: &PolicySettings) -> Vec<Action> {
        self.scanning = true;
        self.active = active;
        self.vpn_seen = env.vpn;
        self.user_paused = false;
        self.env_reason = None;
        self.on_env(env, s)
    }

    /// Handles scan end (`done`/`stopped`).
    pub fn scan_ended(&mut self) {
        *self = Policy::default();
    }

    /// Handles a change of environment or settings.
    pub fn on_env(&mut self, env: &Env, s: &PolicySettings) -> Vec<Action> {
        if !self.scanning {
            return vec![];
        }
        if env.vpn {
            self.vpn_seen = true;
        }
        match self.demand(env, s) {
            Some((r, true)) => {
                self.scan_ended();
                vec![Action::Stop(r)]
            }
            Some((r, false)) => {
                if self.env_reason == Some("android") {
                    return vec![]; // only the user can clear the Android limit
                }
                if self.env_reason == Some(r) {
                    return vec![];
                }
                self.env_reason = Some(r);
                vec![Action::Pause(r)]
            }
            None => match self.env_reason {
                Some("android") | None => vec![],
                Some(_) => {
                    self.env_reason = None;
                    if self.user_paused {
                        // The pause stays, but the reason in the engine becomes the user's.
                        vec![Action::Pause("user")]
                    } else {
                        vec![Action::Resume]
                    }
                }
            },
        }
    }

    /// Handles Android removing the foreground service (the 6 h dataSync limit on Android 15+).
    pub fn on_fgs_timeout(&mut self) -> Vec<Action> {
        if !self.scanning {
            return vec![];
        }
        self.env_reason = Some("android");
        vec![Action::Pause("android")]
    }

    /// Handles the user pressing Pause. `hint` is a reason from the UI (`offline` on network
    /// loss); such hints are not user decisions and are managed by the policy itself.
    pub fn user_pause(&mut self, hint: Option<&str>) -> Vec<Action> {
        if !self.scanning {
            return vec![Action::Pause("user")];
        }
        if matches!(hint, Some(h) if h != "user") {
            return vec![];
        }
        self.user_paused = true;
        match self.env_reason {
            Some(_) => vec![], // already paused by the environment; the engine keeps that reason
            None => vec![Action::Pause("user")],
        }
    }

    /// Handles the user pressing Resume.
    ///
    /// # Errors
    ///
    /// Returns the blocking reason if an environment reason is still in effect.
    pub fn user_resume(&mut self, hint: Option<&str>) -> Result<Vec<Action>, &'static str> {
        if !self.scanning {
            return Ok(vec![Action::Resume]);
        }
        if matches!(hint, Some(h) if h != "user") {
            return Ok(vec![]);
        }
        self.user_paused = false;
        match self.env_reason {
            Some("android") => {
                self.env_reason = None;
                Ok(vec![Action::Resume])
            }
            Some(r) => Err(r),
            None => Ok(vec![Action::Resume]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wifi() -> Env {
        Env {
            transport: Transport::Wifi,
            ..Env::default()
        }
    }

    #[test]
    fn offline_pauses_and_resumes() {
        let s = PolicySettings::default();
        let mut p = Policy::new();
        assert!(p.scan_started(false, &wifi(), &s).is_empty());
        let off = Env {
            online: false,
            transport: Transport::None,
            ..wifi()
        };
        assert_eq!(p.on_env(&off, &s), vec![Action::Pause("offline")]);
        assert_eq!(p.on_env(&off, &s), vec![]);
        assert_eq!(p.on_env(&wifi(), &s), vec![Action::Resume]);
        assert_eq!(p.env_reason(), None);
    }

    #[test]
    fn user_pause_survives_env_recovery() {
        let s = PolicySettings::default();
        let mut p = Policy::new();
        p.scan_started(false, &wifi(), &s);
        assert_eq!(p.user_pause(None), vec![Action::Pause("user")]);
        let off = Env {
            online: false,
            ..wifi()
        };
        assert_eq!(p.on_env(&off, &s), vec![Action::Pause("offline")]);
        assert_eq!(p.on_env(&wifi(), &s), vec![Action::Pause("user")]);
        assert_eq!(p.user_resume(None), Ok(vec![Action::Resume]));
    }

    #[test]
    fn ui_offline_hint_is_not_user_pause() {
        let s = PolicySettings::default();
        let mut p = Policy::new();
        p.scan_started(false, &wifi(), &s);
        let off = Env {
            online: false,
            ..wifi()
        };
        p.on_env(&off, &s);
        assert_eq!(p.user_pause(Some("offline")), vec![]);
        assert!(!p.user_paused());
        assert_eq!(p.user_resume(Some("offline")), Ok(vec![]));
        assert_eq!(p.on_env(&wifi(), &s), vec![Action::Resume]);
    }

    #[test]
    fn resume_blocked_while_env_reason() {
        let s = PolicySettings {
            wifi_only: true,
            ..Default::default()
        };
        let mut p = Policy::new();
        p.scan_started(false, &wifi(), &s);
        let cell = Env {
            transport: Transport::Cellular,
            ..wifi()
        };
        assert_eq!(p.on_env(&cell, &s), vec![Action::Pause("wifi")]);
        assert_eq!(p.user_resume(None), Err("wifi"));
        assert_eq!(p.on_env(&wifi(), &s), vec![Action::Resume]);
    }

    #[test]
    fn wifi_only_pauses_on_start_over_cellular() {
        let s = PolicySettings {
            wifi_only: true,
            ..Default::default()
        };
        let mut p = Policy::new();
        let cell = Env {
            transport: Transport::Cellular,
            ..wifi()
        };
        assert_eq!(
            p.scan_started(false, &cell, &s),
            vec![Action::Pause("wifi")]
        );
    }

    #[test]
    fn vpn_drop_kill_switch() {
        let s = PolicySettings {
            kill_switch: true,
            kill_stop: false,
            ..Default::default()
        };
        let vpn = Env {
            vpn: true,
            ..wifi()
        };
        // Passive scan with kill_action = pause: pause, then resume when the tunnel comes back.
        let mut p = Policy::new();
        p.scan_started(false, &vpn, &s);
        assert_eq!(p.on_env(&wifi(), &s), vec![Action::Pause("vpn")]);
        assert_eq!(p.on_env(&vpn, &s), vec![Action::Resume]);
        // Active mode always stops.
        let mut p = Policy::new();
        p.scan_started(true, &vpn, &s);
        assert_eq!(p.on_env(&wifi(), &s), vec![Action::Stop("vpn")]);
        assert!(!p.scanning());
        // No tunnel before, so nothing can drop.
        let mut p = Policy::new();
        p.scan_started(true, &wifi(), &s);
        assert_eq!(p.on_env(&wifi(), &s), vec![]);
        // Kill switch disabled: nothing happens.
        let off = PolicySettings::default();
        let mut p = Policy::new();
        p.scan_started(true, &vpn, &off);
        assert_eq!(p.on_env(&wifi(), &off), vec![]);
    }

    #[test]
    fn battery_threshold_pause_or_stop() {
        let mut s = PolicySettings {
            batt_on: true,
            batt: 20,
            ..Default::default()
        };
        let low = Env {
            battery: Some(15),
            ..wifi()
        };
        let charging = Env {
            charging: true,
            ..low.clone()
        };
        let mut p = Policy::new();
        p.scan_started(false, &wifi(), &s);
        assert_eq!(p.on_env(&low, &s), vec![Action::Pause("battery")]);
        assert_eq!(p.on_env(&charging, &s), vec![Action::Resume]);
        s.batt_stop = true;
        assert_eq!(p.on_env(&low, &s), vec![Action::Stop("battery")]);
    }

    #[test]
    fn heat_and_charge_only() {
        let s = PolicySettings {
            heat: true,
            ..Default::default()
        };
        let hot = Env {
            thermal: 4,
            ..wifi()
        };
        let mut p = Policy::new();
        p.scan_started(false, &wifi(), &s);
        assert_eq!(p.on_env(&hot, &s), vec![Action::Pause("thermal")]);
        assert_eq!(p.on_env(&wifi(), &s), vec![Action::Resume]);

        let s = PolicySettings {
            charge_only: true,
            ..Default::default()
        };
        let mut p = Policy::new();
        let unplugged = Env {
            battery: Some(80),
            ..wifi()
        };
        assert_eq!(
            p.scan_started(false, &unplugged, &s),
            vec![Action::Pause("battery")]
        );
    }

    #[test]
    fn fgs_timeout_needs_user() {
        let s = PolicySettings::default();
        let mut p = Policy::new();
        p.scan_started(false, &wifi(), &s);
        assert_eq!(p.on_fgs_timeout(), vec![Action::Pause("android")]);
        assert_eq!(p.on_env(&wifi(), &s), vec![]);
        assert_eq!(p.user_resume(None), Ok(vec![Action::Resume]));
    }

    #[test]
    fn idle_policy_is_noop() {
        let s = PolicySettings::default();
        let mut p = Policy::new();
        let off = Env {
            online: false,
            ..wifi()
        };
        assert_eq!(p.on_env(&off, &s), vec![]);
        assert_eq!(p.on_fgs_timeout(), vec![]);
        assert_eq!(p.user_pause(None), vec![Action::Pause("user")]);
    }

    #[test]
    fn mobile_cap_pauses_on_mobile_and_resumes_on_wifi() {
        let s = PolicySettings::default();
        let cell = Env {
            transport: Transport::Cellular,
            metered: true,
            ..Env::default()
        };
        let capped = Env {
            mobile_cap: true,
            ..cell.clone()
        };
        let mut p = Policy::new();
        assert!(p.scan_started(false, &cell, &s).is_empty());
        assert_eq!(p.on_env(&capped, &s), vec![Action::Pause("mobile_cap")]);
        assert_eq!(p.on_env(&capped, &s), vec![]);
        // the user cannot resume over the cap while still on mobile data
        assert_eq!(p.user_resume(None), Err("mobile_cap"));
        // Wi-Fi: the counter stays reached, but the cap no longer applies
        let wifi_capped = Env {
            mobile_cap: true,
            ..wifi()
        };
        assert_eq!(p.on_env(&wifi_capped, &s), vec![Action::Resume]);
        // back on mobile data: paused again
        assert_eq!(p.on_env(&capped, &s), vec![Action::Pause("mobile_cap")]);
        // a raised limit clears the cap
        assert_eq!(p.on_env(&cell, &s), vec![Action::Resume]);
    }

    #[test]
    fn mobile_cap_on_start_and_metered_wifi() {
        let s = PolicySettings::default();
        let metered_wifi = Env {
            metered: true,
            mobile_cap: true,
            ..wifi()
        };
        assert!(metered_wifi.on_mobile());
        let mut p = Policy::new();
        assert_eq!(
            p.scan_started(false, &metered_wifi, &s),
            vec![Action::Pause("mobile_cap")]
        );
        // Wi-Fi only wins over the cap: the reason stays `wifi`
        let s = PolicySettings {
            wifi_only: true,
            ..Default::default()
        };
        let capped_cell = Env {
            transport: Transport::Cellular,
            mobile_cap: true,
            ..Env::default()
        };
        let mut p = Policy::new();
        assert_eq!(
            p.scan_started(false, &capped_cell, &s),
            vec![Action::Pause("wifi")]
        );
        // offline is not mobile
        let off = Env {
            online: false,
            ..capped_cell
        };
        assert!(!off.on_mobile());
    }

    #[test]
    fn transport_parse() {
        assert_eq!(Transport::parse("wifi"), Transport::Wifi);
        assert_eq!(Transport::parse("cellular").as_str(), "cellular");
        assert_eq!(Transport::parse("bluetooth"), Transport::Other);
        assert_eq!(Transport::parse(""), Transport::None);
    }
}
