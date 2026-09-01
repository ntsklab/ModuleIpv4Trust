var Ipv4TrustIndex = {
    $formObj: $('#ipv4-trust-form'),

    initialize() {
        $('#ipv4-trust-recheck').on('click', function () {
            Ipv4TrustIndex.refreshLiveStatus();
        });

        Ipv4TrustIndex.initializeForm();
        Ipv4TrustIndex.refreshLiveStatus();
    },

    refreshLiveStatus() {
        $.ajax({
            url: Config.pbxUrl + '/pbxcore/api/modules/ModuleIpv4Trust/firewall-status',
            method: 'POST',
            dataType: 'json',
            success: function (response) {
                if (!response || response.result !== true || !response.data) {
                    return;
                }
                var data = response.data;
                $('#live-ipv4').text(data.currentAddress ? data.currentAddress : 'not detected');
                $('#live-rule').text(data.ownAddressRule ? 'Active (' + data.ownAddressRule + ')' : 'Inactive');
            }
        });
    },

    cbBeforeSendForm(settings) {
        const result = settings;
        result.data = Ipv4TrustIndex.$formObj.form('get values');
        return result;
    },

    cbAfterSendForm(response) {
        if (response.success === true) {
            window.location = window.location.href;
        }
    },

    initializeForm() {
        Form.$formObj = Ipv4TrustIndex.$formObj;
        Form.url = globalRootUrl + 'module-ipv4-trust/module-ipv4-trust/save';
        Form.validateRules = {};
        Form.cbBeforeSendForm = Ipv4TrustIndex.cbBeforeSendForm;
        Form.cbAfterSendForm = Ipv4TrustIndex.cbAfterSendForm;
        Form.initialize();
    }
};

$(document).ready(function () {
    Ipv4TrustIndex.initialize();
});