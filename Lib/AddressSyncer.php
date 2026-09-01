<?php

declare(strict_types=1);

namespace Modules\ModuleIpv4Trust\Lib;

use MikoPBX\Common\Models\NetworkFilters;
use MikoPBX\Core\System\Configs\Fail2BanConf;
use MikoPBX\Core\System\Configs\IptablesConf;
use Modules\ModuleIpv4Trust\Models\ModuleIpv4TrustSettings;

/**
 * Keeps the fail2ban trust rule (NetworkFilters row with newer_block_ip=1)
 * in sync with the current global IPv4 address. The address can change at any
 * time (ISP re-assignment, NAT restart), so this is called on every relevant
 * event: settings change, network reconfiguration, boot and a periodic cron check.
 */
class AddressSyncer
{
    public const FILTER_MARKER = 'ModuleIpv4Trust: trusted own IPv4 address';

    /**
     * Syncs the trust row and reloads fail2ban + firewall when something changed.
     */
    public static function run(): void
    {
        $changed = self::syncRow();
        if (!$changed) {
            return;
        }

        $fail2ban = new Fail2BanConf();
        $fail2ban->reStart();

        IptablesConf::updateFirewallRules();
        IptablesConf::reloadFirewall();
    }

    /**
     * Updates the NetworkFilters row to match the current settings and address.
     * Returns true when the row was created, updated or deleted.
     */
    public static function syncRow(): bool
    {
        $settings = ModuleIpv4TrustSettings::findFirst();
        $enabled = $settings !== null && $settings->allowOwnAddress === '1';

        $filter = NetworkFilters::findFirstByDescription(self::FILTER_MARKER);

        if (!$enabled) {
            if ($filter === null) {
                return false;
            }
            return $filter->delete() === true;
        }

        $address = Ipv4TrustHelper::getGlobalIpv4Address();
        if ($address === '' || !Ipv4TrustHelper::isUsableAddress($address)) {
            return false;
        }
        $cidr = "{$address}/32";

        if ($filter !== null && $filter->permit === $cidr) {
            return false;
        }

        if ($filter === null) {
            $filter = new NetworkFilters();
        }
        $filter->permit = $cidr;
        $filter->deny = '0.0.0.0/0';
        $filter->newer_block_ip = '1';
        $filter->local_network = '0';
        $filter->description = self::FILTER_MARKER;
        $filter->priority = '0';

        return $filter->save() === true;
    }
}