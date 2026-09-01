<?php

declare(strict_types=1);

namespace Modules\ModuleIpv4Trust\Lib;

use MikoPBX\Core\System\Util;
use Modules\ModuleIpv4Trust\Models\ModuleIpv4TrustSettings;

class Ipv4TrustHelper
{
    private const DEFAULT_IPV4_URL = 'https://ipinfo-v4.in-deep.blue/ip';

    /**
     * Returns the PBX public IPv4 address as seen from outside (NAT global address).
     * Uses the configured external service, falling back to the default URL.
     */
    public static function getGlobalIpv4Address(): string
    {
        $settings = ModuleIpv4TrustSettings::findFirst();
        $url = !empty($settings?->ipv4ServiceUrl) ? $settings->ipv4ServiceUrl : self::DEFAULT_IPV4_URL;

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_IPRESOLVE => CURL_IPRESOLVE_V4,
        ]);
        $body = curl_exec($ch);
        curl_close($ch);
        if ($body === false) {
            return '';
        }

        $ip = trim($body);
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false ? $ip : '';
    }

    /**
     * Checks whether the given address can be used by the module.
     * Private/loopback/link-local addresses are useless for hairpin NAPT.
     */
    public static function isUsableAddress(string $address): bool
    {
        return filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false
            && !filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
    }

    public static function whichIptables(): string
    {
        return (string)Util::which('iptables');
    }
}