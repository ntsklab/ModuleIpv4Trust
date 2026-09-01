<?php

declare(strict_types=1);

namespace Modules\ModuleIpv4Trust\App\Controllers;

use MikoPBX\AdminCabinet\Controllers\BaseController;
use MikoPBX\AdminCabinet\Providers\AssetProvider;
use MikoPBX\Common\Models\NetworkFilters;
use MikoPBX\Modules\PbxExtensionUtils;
use Modules\ModuleIpv4Trust\App\Forms\Ipv4TrustForm;
use Modules\ModuleIpv4Trust\Lib\AddressSyncer;
use Modules\ModuleIpv4Trust\Models\ModuleIpv4TrustSettings;

class ModuleIpv4TrustController extends BaseController
{
    private string $moduleUniqueID = 'ModuleIpv4Trust';
    private string $moduleDir;

    public function initialize(): void
    {
        $this->moduleDir = PbxExtensionUtils::getModuleDir($this->moduleUniqueID);
        $this->view->logoImagePath = '';
        $this->view->submitMode = null;
        parent::initialize();
    }

    public function indexAction(): void
    {
        $footerCollection = $this->assets->collection(AssetProvider::FOOTER_JS);
        $footerCollection->addJs('js/pbx/main/form.js', true);
        $footerCollection->addJs("js/cache/{$this->moduleUniqueID}/ipv4-trust-index.js", true);

        $settings = ModuleIpv4TrustSettings::findFirst();
        if ($settings === null) {
            $settings = new ModuleIpv4TrustSettings();
        }

        $this->view->form = new Ipv4TrustForm($settings);
        $this->view->record = $settings;
        $this->view->trustRowExists = NetworkFilters::findFirstByDescription(AddressSyncer::FILTER_MARKER) !== null;
        $this->view->pick("{$this->moduleDir}/App/Views/Ipv4Trust/index");
    }

    public function saveAction(): void
    {
        if (!$this->request->isPost()) {
            return;
        }

        $data = $this->request->getPost();

        $record = ModuleIpv4TrustSettings::findFirst();
        if ($record === null) {
            $record = new ModuleIpv4TrustSettings();
        }

        $record->allowOwnAddress = isset($data['allowOwnAddress']) && $data['allowOwnAddress'] === 'on' ? '1' : '0';
        $record->ipv4ServiceUrl = $data['ipv4ServiceUrl'] ?? '';

        if ($this->saveEntity($record) === false) {
            return;
        }

        AddressSyncer::syncRow();
    }
}