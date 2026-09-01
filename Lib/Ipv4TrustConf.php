<?php

declare(strict_types=1);

namespace Modules\ModuleIpv4Trust\Lib;

use MikoPBX\Common\Models\NetworkFilters;
use MikoPBX\Core\System\Util;
use MikoPBX\Modules\Config\ConfigClass;
use MikoPBX\Modules\PbxExtensionUtils;
use MikoPBX\PBXCoreREST\Lib\PBXApiResult;
use Modules\ModuleIpv4Trust\Models\ModuleIpv4TrustSettings;

class Ipv4TrustConf extends ConfigClass
{
    private const MODULE_UNIQUE_ID = 'ModuleIpv4Trust';

    /**
     * Injects the own /32 ACCEPT rule on every firewall reload.
     *
     * Delegates to Ipv4TrustRules::syncDynamic() so the reload path and the
     * dynamic path produce the identical rule set. During a reload the core has
     * not yet appended its terminal DROP, so syncDynamic() falls back to
     * appending (which lands before the DROP that the core adds afterwards).
     */
    public function onAfterIptablesReload(): void
    {
        if (!PbxExtensionUtils::isEnabled(self::MODULE_UNIQUE_ID)) {
            return;
        }
        Ipv4TrustRules::syncDynamic();
    }

    public function createCronTasks(array &$tasks): void
    {
        if (!PbxExtensionUtils::isEnabled(self::MODULE_UNIQUE_ID)) {
            return;
        }

        $phpPath = Util::which('php');
        $moduleDir = PbxExtensionUtils::getModuleDir(self::MODULE_UNIQUE_ID);

        $tasks[] = "*/5 * * * * {$phpPath} -f {$moduleDir}/bin/check-address.php > /dev/null 2>&1" . PHP_EOL;
    }

    public function onAfterNetworkConfigured(): void
    {
        if (!PbxExtensionUtils::isEnabled(self::MODULE_UNIQUE_ID)) {
            return;
        }
        AddressSyncer::run();
    }

    public function onAfterPbxStarted(): void
    {
        if (!PbxExtensionUtils::isEnabled(self::MODULE_UNIQUE_ID)) {
            return;
        }
        AddressSyncer::run();
    }

    public function modelsEventChangeData($data): void
    {
        if (($data['model'] ?? '') !== ModuleIpv4TrustSettings::class) {
            return;
        }
        AddressSyncer::run();
        Ipv4TrustRules::syncDynamic();
    }

    /**
     * Handles /pbxcore/api/modules/ModuleIpv4Trust/{action} requests under root rights.
     * 'firewall-status' re-syncs the rules and returns the actual live firewall state.
     */
    public function moduleRestAPICallback(array $request): PBXApiResult
    {
        $res = new PBXApiResult();
        $res->processor = __METHOD__;
        $res->function = $request['action'] ?? '';

        return match ($res->function) {
            'firewall-status' => $this->firewallStatusAction($res),
            default => $this->firewallStatusError($res, "Unknown action: {$res->function}"),
        };
    }

    private function firewallStatusAction(PBXApiResult $res): PBXApiResult
    {
        AddressSyncer::run();
        Ipv4TrustRules::syncDynamic();

        $status = Ipv4TrustRules::getLiveStatus();

        $res->success = true;
        $res->data = [
            'ownAddressRule' => $status['ownAddressRule'],
            'currentAddress' => Ipv4TrustHelper::getGlobalIpv4Address(),
            'fail2banTrust' => NetworkFilters::findFirstByDescription(AddressSyncer::FILTER_MARKER) !== null,
        ];

        return $res;
    }

    private function firewallStatusError(PBXApiResult $res, string $message): PBXApiResult
    {
        $res->messages['error'][] = $message;
        return $res;
    }
}