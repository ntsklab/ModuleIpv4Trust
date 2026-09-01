<?php

declare(strict_types=1);

namespace Modules\ModuleIpv4Trust\Lib;

use MikoPBX\Common\Models\NetworkFilters;
use MikoPBX\Core\System\Processes;
use MikoPBX\Core\System\Util;
use Modules\ModuleIpv4Trust\Models\ModuleIpv4TrustSettings;

/**
 * Dynamically injects / removes the module rules in the live IPv4 firewall.
 *
 * The hooks (onAfterIptablesReload) cover the boot / full-reload path; this
 * class applies the same rules immediately when the settings change, without
 * a full firewall rebuild. Both paths produce the identical rule set.
 */
class Ipv4TrustRules
{
    /**
     * Aligns the live INPUT chain with the current settings.
     *
     * The core firewall appends its terminal catch-all `-A INPUT -j DROP` as
     * the last rule. The own /32 ACCEPT must sit *before* that DROP to allow
     * hairpin NAPT traffic. Because `syncDynamic()` runs after a reload (DROP
     * already present), a plain `-A` append would land after the DROP and do
     * nothing. We delete any existing copy of the rule (healing previously
     * misplaced ones) and re-insert it before the terminal DROP; when no DROP
     * exists yet we fall back to appending.
     */
    public static function syncDynamic(): void
    {
        $iptables = Ipv4TrustHelper::whichIptables();
        if (empty($iptables)) {
            return;
        }

        $settings = ModuleIpv4TrustSettings::findFirst();
        $enabled = $settings !== null && $settings->allowOwnAddress === '1';

        $currentAddress = Ipv4TrustHelper::getGlobalIpv4Address();
        $trustRow = NetworkFilters::findFirstByDescription(AddressSyncer::FILTER_MARKER);
        $oldCidr = $trustRow !== null ? (string)$trustRow->permit : '';

        $desiredCidr = '';
        if ($enabled && $currentAddress !== '' && Ipv4TrustHelper::isUsableAddress($currentAddress)) {
            $desiredCidr = "{$currentAddress}/32";
        }

        $moduleCidrs = array_unique(array_filter([$desiredCidr, $oldCidr]));

        $dropPos = self::getDropPosition($iptables);

        foreach ($moduleCidrs as $cidr) {
            self::setRule($iptables, $dropPos, "-s {$cidr} -j ACCEPT", $cidr === $desiredCidr);
        }
    }

    /**
     * Returns the 1-based iptables RULE position of the terminal catch-all
     * DROP in the INPUT chain, or 0 if there is no such rule. `-S INPUT` prints
     * the policy line (`-P INPUT …`) first, so only `-A INPUT` lines count.
     */
    private static function getDropPosition(string $iptables): int
    {
        $out = [];
        Processes::mwExec("{$iptables} -S INPUT", $out);
        $rulePos = 0;
        foreach ($out as $line) {
            $line = trim($line);
            if (!str_starts_with($line, '-A INPUT')) {
                continue;
            }
            $rulePos++;
            if ($line === '-A INPUT -j DROP') {
                return $rulePos;
            }
        }
        return 0;
    }

    /**
     * Makes a module rule active or inactive, placed before the terminal DROP.
     */
    private static function setRule(string $iptables, int $dropPos, string $rule, bool $active): void
    {
        Processes::mwExec("while {$iptables} -D INPUT {$rule} 2>/dev/null; do :; done");
        if (!$active) {
            return;
        }
        if ($dropPos > 0) {
            Processes::mwExec("{$iptables} -I INPUT {$dropPos} {$rule}");
        } else {
            Processes::mwExec("{$iptables} -A INPUT {$rule}");
        }
    }

    /**
     * Returns the actual live state of the module rule in the IPv4 firewall.
     * Only rules matching a module-managed address are reported — the core
     * firewall itself contains e.g. "127.0.0.1/32" ACCEPT rules that must
     * not be mistaken for the module rule.
     *
     * @return array<string, mixed> ownAddressRule (e.g. "1.2.3.4/32") or empty string
     */
    public static function getLiveStatus(): array
    {
        $iptables = Ipv4TrustHelper::whichIptables();
        if (empty($iptables)) {
            return ['ownAddressRule' => ''];
        }

        $candidates = [];
        $currentAddress = Ipv4TrustHelper::getGlobalIpv4Address();
        if ($currentAddress !== '') {
            $candidates[] = "{$currentAddress}/32";
        }
        $trustRow = NetworkFilters::findFirstByDescription(AddressSyncer::FILTER_MARKER);
        if ($trustRow !== null && !empty($trustRow->permit)) {
            $candidates[] = (string)$trustRow->permit;
        }
        if (empty($candidates)) {
            return ['ownAddressRule' => ''];
        }

        $out = [];
        Processes::mwExec("{$iptables} -S INPUT", $out);
        foreach ($out as $line) {
            if (preg_match('/-s\s+(\S+)\s+-j\s+ACCEPT/', $line, $m) !== 1) {
                continue;
            }
            if (in_array($m[1], $candidates, true)) {
                return ['ownAddressRule' => $m[1]];
            }
        }

        return ['ownAddressRule' => ''];
    }
}