var Ipv4TrustIndex = {
    $formObj: $('#ipv4-trust-form'),
    $recheckBtn: $('#ipv4-trust-recheck'),
    $feedback: $('#ipv4-trust-recheck-feedback'),

    initialize() {
        $('#ipv4-trust-recheck').on('click', function () {
            Ipv4TrustIndex.refreshLiveStatus();
        });

        Ipv4TrustIndex.initializeForm();
        Ipv4TrustIndex.refreshLiveStatus();
    },

    refreshLiveStatus() {
        Ipv4TrustIndex.$feedback.hide();
        Ipv4TrustIndex.$recheckBtn
            .addClass('loading disabled')
            .find('.sync')
            .addClass('loading');

        $.ajax({
            url: Config.pbxUrl + '/pbxcore/api/modules/ModuleIpv4Trust/firewall-status',
            method: 'POST',
            dataType: 'json',
            success: function (response) {
                Ipv4TrustIndex.recheckDone(false, response);
            },
            error: function () {
                Ipv4TrustIndex.recheckDone(true);
            }
        });
    },

    recheckDone(isError, response) {
        Ipv4TrustIndex.$recheckBtn
            .removeClass('loading disabled')
            .find('.sync')
            .removeClass('loading');

        if (isError || !response || response.result !== true || !response.data) {
            Ipv4TrustIndex.showFeedback('error', 'Re-check failed. The IPv4 firewall state could not be read.');
            return;
        }

        var data = response.data;
        $('#live-ipv4').text(data.currentAddress ? data.currentAddress : 'not detected');
        $('#live-rule').text(data.ownAddressRule ? 'Active (' + data.ownAddressRule + ')' : 'Inactive');
        $('#live-trust').text(data.fail2banTrust ? 'Active' : 'Inactive');

        Ipv4TrustIndex.showFeedback('positive', 'Re-checked: ' + new Date().toLocaleTimeString() + '.');
    },

    showFeedback(type, message) {
        Ipv4TrustIndex.$feedback
            .removeClass('hidden error positive')
            .addClass(type)
            .text(message)
            .show();
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