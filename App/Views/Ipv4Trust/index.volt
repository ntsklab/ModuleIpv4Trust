<form class="ui large grey segment form" id="ipv4-trust-form">

    <h4 class="ui dividing header">IPv4 firewall rules</h4>

    <div class="field">
        <div class="ui toggle checkbox">
            <input type="checkbox" name="allowOwnAddress" {{ record.allowOwnAddress == '1' ? 'checked' : '' }}>
            <label>Trust the PBX own global IPv4 address</label>
        </div>
        <div class="ui small grey text">Allows all traffic from the PBX public IPv4 address (/32) in the firewall and adds it to the fail2ban "trusted addresses" (ignoreip) list. Use it for hairpin NAPT setups, where the PBX connects to its own public address (e.g. self-registration via the public IP) and must never be blocked, even after repeated login failures.</div>
    </div>

    <div class="field">
        <label>External IPv4 detection service URL</label>
        <input type="text" name="ipv4ServiceUrl" value="{{ record.ipv4ServiceUrl }}" placeholder="https://ipinfo-v4.in-deep.blue/ip">
        <div class="ui small grey text">Returns the public IPv4 address as seen from outside (NAT global address).</div>
    </div>

    <div class="ui segment">
        <h4 class="ui dividing header">Status</h4>
        <table class="ui very compact definition table">
            <tbody>
                <tr>
                    <td>Current global IPv4 address</td>
                    <td><span id="live-ipv4">-</span></td>
                </tr>
                <tr>
                    <td>Fail2ban trust rule</td>
                    <td>{{ trustRowExists ? 'Active' : 'Inactive' }}</td>
                </tr>
                <tr>
                    <td>IPv4 firewall: own /32 ACCEPT</td>
                    <td><span id="live-rule">-</span></td>
                </tr>
            </tbody>
        </table>
        <button type="button" class="ui basic blue button" id="ipv4-trust-recheck">
            <i class="sync icon"></i> Re-check
        </button>
    </div>

    {{ partial("partials/submitbutton",['indexurl':'pbx-extension-modules/index/']) }}
</form>