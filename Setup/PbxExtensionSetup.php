<?php

declare(strict_types=1);

namespace Modules\ModuleIpv4Trust\Setup;

use MikoPBX\Common\Models\PbxExtensionModules;
use MikoPBX\Common\Models\PbxSettings;
use MikoPBX\Modules\Setup\PbxExtensionSetupBase;

class PbxExtensionSetup extends PbxExtensionSetupBase
{
    private const MODULE_NAME = 'Own IPv4 Trust';
    private const MODULE_DESCRIPTION = 'Trusts the PBX own global IPv4 address in the firewall and fail2ban';

    public function installDB(): bool
    {
        $result = $this->createSettingsTableByModelsAnnotations();
        if ($result) {
            $result = $this->registerNewModule();
        }
        if ($result) {
            $result = $this->addToSidebar();
        }
        return $result;
    }

    public function registerNewModule(): bool
    {
        $module = PbxExtensionModules::findFirstByUniqid($this->moduleUniqueID);
        if ($module === null) {
            $module = new PbxExtensionModules();
            $module->disabled = '1';
        }
        $module->uniqid = $this->moduleUniqueID;
        $module->name = self::MODULE_NAME;
        $module->description = self::MODULE_DESCRIPTION;
        $module->developer = $this->developer;
        $module->version = $this->version;
        $module->support_email = $this->support_email;
        $module->module_type = $this->module_type;

        return $module->save();
    }

    public function addToSidebar(): bool
    {
        $menuSettingsKey = "AdditionalMenuItem{$this->moduleUniqueID}";
        $menuSettings = PbxSettings::findFirstByKey($menuSettingsKey);
        if ($menuSettings === null) {
            $menuSettings = new PbxSettings();
            $menuSettings->key = $menuSettingsKey;
        }
        $value = [
            'uniqid'        => $this->moduleUniqueID,
            'group'         => 'networkSettings',
            'iconClass'     => 'shield alternate',
            'caption'       => self::MODULE_NAME,
            'showAtSidebar' => true,
        ];
        $menuSettings->value = json_encode($value);
        return $menuSettings->save();
    }
}