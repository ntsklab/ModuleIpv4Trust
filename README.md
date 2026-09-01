# ModuleIpv4Trust — Own global IPv4 address trust for MikoPBX

MikoPBX module that trusts the PBX own **global IPv4 address** in the built-in firewall and in fail2ban, for hairpin NAPT setups.

## Background

With hairpin NAPT, the PBX (or devices behind the same NAT) may reach the PBX through its **public** IPv4 address — e.g. self-registration against a provider through the public IP. Those connections arrive with the PBX public address as the source, and repeated login/registration failures from that address can get it blocked by the firewall and by fail2ban — locking the PBX out of itself.

This module makes the PBX own public IPv4 address a trusted address:

- **Firewall**: adds `iptables -A INPUT -s <global-ip>/32 -j ACCEPT` before the final DROP.
- **Fail2ban**: adds the `/32` to the "trusted addresses" (`ignoreip`) list via a `NetworkFilters` row (`newer_block_ip=1`), so it is never blocked, even after repeated login failures.

## Detection

The public IPv4 address is detected through an external service (default `https://ipinfo-v4.in-deep.blue/ip`, configurable in the settings page). Private / reserved addresses are ignored.

### Address change tracking

The global IPv4 address can change (ISP re-assignment, NAT restart). The module re-syncs the trust rule:

- on settings change (asynchronous worker, root rights)
- on network reconfiguration (`onAfterNetworkConfigured`)
- on PBX start (`onAfterPbxStarted`)
- every 5 minutes via cron (`bin/check-address.php`)

### Rule application paths

- **Dynamic**: the rule is added/removed live (via `iptables`) immediately when the settings change — no reboot required.
- **Hook**: the rule is re-injected on every firewall rebuild (boot / config reload) via `onAfterIptablesReload`.

## Architecture note

The admin-cabinet web UI runs as the unprivileged `www` user, which cannot touch `iptables` (`/var/run/xtables.lock` is root-only). All live firewall operations therefore go through root-rights paths:

- `modelsEventChangeData` hook (async worker)
- `bin/check-address.php` (cron)
- module REST callback `POST /pbxcore/api/modules/ModuleIpv4Trust/firewall-status` (used by the settings page to display the actual live rule state)

## Installation

1. Zip the module directory (`module.json` must be at the archive root).
2. MikoPBX UI: **Modules → Install module** → upload the zip.
3. Enable the module, open the settings page (sidebar → network settings group → "Own IPv4 Trust"), enable the toggle and save.

Requires MikoPBX 2026.1.223 or newer. Tested on MikoPBX 2026.3.40.

## Files

```
ModuleIpv4Trust/
├── module.json
├── Setup/PbxExtensionSetup.php      # install: settings table, module record, sidebar
├── Models/ModuleIpv4TrustSettings.php
├── Lib/
│   ├── Ipv4TrustConf.php            # ConfigClass hooks + REST callback
│   ├── Ipv4TrustHelper.php          # public IPv4 detection / validation
│   ├── Ipv4TrustRules.php           # dynamic add/remove + live status
│   └── AddressSyncer.php            # fail2ban trust row (NetworkFilters) sync
├── bin/check-address.php            # periodic address check (cron)
├── App/                             # admin-cabinet UI (controller, view, form)
├── Messages/                        # ru/en/ja translations
└── public/assets/js/                # settings page JS
```