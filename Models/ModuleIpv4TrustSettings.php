<?php

declare(strict_types=1);

namespace Modules\ModuleIpv4Trust\Models;

use MikoPBX\Modules\Models\ModulesModelsBase;

class ModuleIpv4TrustSettings extends ModulesModelsBase
{
    /**
     * @Primary
     * @Identity
     * @Column(type="integer", nullable=false)
     */
    public $id;

    /**
     * Trust the PBX own global IPv4 address: firewall ACCEPT /32 + fail2ban ignoreip: 1 = enabled
     * @Column(type="string", nullable=true, default="0")
     */
    public ?string $allowOwnAddress = '0';

    /**
     * External IPv4 detection service URL (returns the public IPv4 address)
     * @Column(type="string", nullable=true, default="https://ipinfo-v4.in-deep.blue/ip")
     */
    public ?string $ipv4ServiceUrl = 'https://ipinfo-v4.in-deep.blue/ip';

    public function initialize(): void
    {
        $this->setSource('m_ModuleIpv4TrustSettings');
        parent::initialize();
    }
}