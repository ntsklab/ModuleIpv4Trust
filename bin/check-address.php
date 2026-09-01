<?php

declare(strict_types=1);

require_once 'Globals.php';

use MikoPBX\Modules\PbxExtensionUtils;
use Modules\ModuleIpv4Trust\Lib\AddressSyncer;
use Modules\ModuleIpv4Trust\Lib\Ipv4TrustRules;

if (!PbxExtensionUtils::isEnabled('ModuleIpv4Trust')) {
    exit(0);
}

AddressSyncer::run();
Ipv4TrustRules::syncDynamic();

exit(0);