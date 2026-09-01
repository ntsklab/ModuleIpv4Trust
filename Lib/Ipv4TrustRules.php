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
     * Aligns the live INPUT chain with the current settings:
     * adds the missing /32 ACCEPT rule, removes a stale one.
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
        if (empty($moduleCidrs)) {
            return;
        }

        $presentCidrs = [];

        $out = [];
        Processes::mwExec("{$iptables} -S INPUT", $out);
        foreach ($out as $line) {
            if (preg_match('/-s\s+(\S+)\s+-j\s+ACCEPT/', $line, $m) !== 1) {
                continue;
            }
            if (in_array($m[1], $moduleCidrs, true)) {
                $presentCidrs[$m[1]] = true;
            }
        }

        foreach ($presentCidrs as $present => $_) {
            if ($present !== $desiredCidr) {
                Processes::mwExec("{$iptables} -D INPUT -s {$present} -j ACCEPT");
            }
        }
        if ($desiredCidr !== '' && !isset($presentCidrs[$desiredCidr])) {
            Processes::mwExec("{$iptables} -A INPUT -s {$desiredCidr} -j ACCEPT");
        }
    }

    /**
     * Returns the actual live state of the module rule in the IPv4 firewall.
     *
     * @return array<string, mixed> ownAddressRule (e.g. "1.2.3.4/32") or empty string
     */
    public static function getLiveStatus(): array
    {
        $iptables = Ipv4TrustHelper::whichIptables();
        if (empty($iptables)) {
            return ['ownAddressRule' => ''];
        }

        $ownAddressRule = '';

        $out = [];
        Processes::mwExec("{$iptables} -S INPUT", $out);
        foreach ($out as $line) {
            if (preg_match('/-s\s+(\S+\/32)\s+-j\s+ACCEPT/', $line, $m) === 1) {
                $ownAddressRule = $m[1];
                break;
            }
        }

        return ['ownAddressRule' => $ownAddressRule];
    }
}