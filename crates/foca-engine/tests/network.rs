//! Network stages: infrastructure, ports, recon, brute force, plugins.

mod common;

mod network {
    mod fuzz;
    mod infra;
    mod plugins_scan;
    mod ports;
    mod recon;
}
