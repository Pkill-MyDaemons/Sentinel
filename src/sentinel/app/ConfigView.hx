package sentinel.app;

using StringTools;
using Lambda;

import haxe.ui.ComponentBuilder;
import haxe.ui.containers.VBox;
import haxe.ui.components.Button;
import haxe.ui.components.Label;
import haxe.ui.components.TextField;
import haxe.ui.components.TextArea;
import haxe.ui.components.CheckBox;
import haxe.ui.components.Slider;
import haxe.ui.components.DropDown;
import haxe.ui.components.NumberStepper;
import haxe.ui.core.Component;
import sentinel.config.Config;

/**
 * ConfigView — populates the Config tab and handles save/reset.
 *
 * Correct HaxeUI API (v1.7):
 *   - component.hidden = true/false
 *   - ComponentBuilder.fromFile  (not ComponentMacros.buildComponent)
 *   - DropDown.selectedItem.value to read selected value
 *   - Slider.pos for current value (Float 0.0–1.0 when min/max set)
 *   - NumberStepper.pos for current value
 */
class ConfigView {

    var tabRoot:VBox;
    var root:Component;

    // AI
    var aiProvider:DropDown;
    var aiLocalModel:TextField;
    var aiLocalEndpoint:TextField;
    var aiAnthropicKey:TextField;
    var aiAnthropicModel:TextField;
    var aiOpenAIKey:TextField;
    var aiOpenAIModel:TextField;
    var aiBlockThresh:Slider;
    var aiWarnThresh:Slider;
    var lblBlock:Label;
    var lblWarn:Label;
    var rowsLocal:VBox;
    var rowsAnthropic:VBox;
    var rowsOpenAI:VBox;

    // Terminal
    var termAutoBlock:CheckBox;
    var termGithubToken:TextField;
    var termTrustedTaps:TextArea;

    // Updates
    var updBlockUnknown:CheckBox;
    var updTrustedDomains:TextArea;

    // Extensions
    var extAutoDisable:CheckBox;
    var extMaxPerms:NumberStepper;
    var extDangerousPerms:TextArea;

    // Network
    var netLogConnections:CheckBox;
    var netIgnoredApps:TextArea;

    // Footer
    var btnSave:Button;
    var btnReset:Button;
    var lblSaveStatus:Label;
    var saveTimer:haxe.Timer;

    public function new(appRoot:Component) {
        tabRoot = appRoot.findComponent("tab-config", VBox, true);
        root    = ComponentBuilder.fromFile("assets/config-view.xml");
        tabRoot.addComponent(root);
        cacheRefs();
        bindEvents();
    }

    public function load() {
        var c = Config.get();

        setDropdown(aiProvider, c.ai.provider);
        setText(aiLocalModel,     c.ai.localModel);
        setText(aiLocalEndpoint,  c.ai.localEndpoint);
        setText(aiAnthropicKey,   c.ai.anthropicKey   ?? "");
        setText(aiAnthropicModel, c.ai.anthropicModel ?? "");
        setText(aiOpenAIKey,      c.ai.openaiKey      ?? "");
        setText(aiOpenAIModel,    c.ai.openaiModel    ?? "");
        setSlider(aiBlockThresh, c.ai.blockThreshold, lblBlock);
        setSlider(aiWarnThresh,  c.ai.warnThreshold,  lblWarn);
        updateProviderRows(c.ai.provider);

        if (termAutoBlock   != null) termAutoBlock.selected   = c.terminal.autoBlock;
        setText(termGithubToken, c.terminal.githubToken ?? "");
        if (termTrustedTaps != null) termTrustedTaps.text     = c.terminal.trustedTaps.join("\n");

        if (updBlockUnknown   != null) updBlockUnknown.selected   = c.updates.blockUnknownDomains;
        if (updTrustedDomains != null) updTrustedDomains.text     = c.updates.trustedDomains.join("\n");

        if (extAutoDisable    != null) extAutoDisable.selected    = c.extensions.autoDisable;
        if (extMaxPerms       != null) extMaxPerms.pos             = c.extensions.maxPermissions;
        if (extDangerousPerms != null) extDangerousPerms.text     = c.extensions.dangerousPermissions.join("\n");

        if (netLogConnections != null) netLogConnections.selected = c.network.logConnections;
        if (netIgnoredApps    != null) netIgnoredApps.text        = c.network.ignoredApps.join("\n");
    }

    // ── Private ─────────────────────────────────────────────────────

    function cacheRefs() {
        aiProvider      = root.findComponent("cfg-ai-provider",       DropDown,      true);
        aiLocalModel    = root.findComponent("cfg-ai-localModel",      TextField,     true);
        aiLocalEndpoint = root.findComponent("cfg-ai-localEndpoint",   TextField,     true);
        aiAnthropicKey  = root.findComponent("cfg-ai-anthropicKey",    TextField,     true);
        aiAnthropicModel= root.findComponent("cfg-ai-anthropicModel",  TextField,     true);
        aiOpenAIKey     = root.findComponent("cfg-ai-openaiKey",       TextField,     true);
        aiOpenAIModel   = root.findComponent("cfg-ai-openaiModel",     TextField,     true);
        aiBlockThresh   = root.findComponent("cfg-ai-blockThreshold",  Slider,        true);
        aiWarnThresh    = root.findComponent("cfg-ai-warnThreshold",   Slider,        true);
        lblBlock        = root.findComponent("lbl-block-thresh",       Label,         true);
        lblWarn         = root.findComponent("lbl-warn-thresh",        Label,         true);
        rowsLocal       = root.findComponent("rows-local",             VBox,          true);
        rowsAnthropic   = root.findComponent("rows-anthropic",         VBox,          true);
        rowsOpenAI      = root.findComponent("rows-openai",            VBox,          true);

        termAutoBlock    = root.findComponent("cfg-terminal-autoBlock",   CheckBox,  true);
        termGithubToken  = root.findComponent("cfg-terminal-githubToken", TextField, true);
        termTrustedTaps  = root.findComponent("cfg-terminal-trustedTaps", TextArea,  true);

        updBlockUnknown   = root.findComponent("cfg-updates-blockUnknownDomains", CheckBox, true);
        updTrustedDomains = root.findComponent("cfg-updates-trustedDomains",      TextArea, true);

        extAutoDisable    = root.findComponent("cfg-extensions-autoDisable",         CheckBox,      true);
        extMaxPerms       = root.findComponent("cfg-extensions-maxPermissions",       NumberStepper, true);
        extDangerousPerms = root.findComponent("cfg-extensions-dangerousPermissions", TextArea,      true);

        netLogConnections = root.findComponent("cfg-network-logConnections", CheckBox, true);
        netIgnoredApps    = root.findComponent("cfg-network-ignoredApps",    TextArea, true);

        btnSave       = root.findComponent("btn-save",        Button, true);
        btnReset      = root.findComponent("btn-reset",       Button, true);
        lblSaveStatus = root.findComponent("lbl-save-status", Label,  true);
    }

    function bindEvents() {
        if (aiProvider != null) {
            aiProvider.onChange = (_) ->
                updateProviderRows(aiProvider.selectedItem?.value ?? "local");
        }
        if (aiBlockThresh != null) {
            aiBlockThresh.onChange = (_) -> {
                if (lblBlock != null) lblBlock.text = fmtF(aiBlockThresh.pos);
            };
        }
        if (aiWarnThresh != null) {
            aiWarnThresh.onChange = (_) -> {
                if (lblWarn != null) lblWarn.text = fmtF(aiWarnThresh.pos);
            };
        }
        if (btnSave  != null) btnSave.onClick  = (_) -> save();
        if (btnReset != null) btnReset.onClick = (_) -> load();
    }

    function updateProviderRows(p:String) {
        if (rowsLocal     != null) rowsLocal.hidden     = p != "local";
        if (rowsAnthropic != null) rowsAnthropic.hidden = p != "anthropic";
        if (rowsOpenAI    != null) rowsOpenAI.hidden    = p != "openai";
    }

    function save() {
        var c = Config.get();

        c.ai.provider       = aiProvider?.selectedItem?.value    ?? c.ai.provider;
        c.ai.localModel     = aiLocalModel?.text                 ?? c.ai.localModel;
        c.ai.localEndpoint  = aiLocalEndpoint?.text              ?? c.ai.localEndpoint;
        c.ai.anthropicKey   = aiAnthropicKey?.text               ?? c.ai.anthropicKey;
        c.ai.anthropicModel = aiAnthropicModel?.text             ?? c.ai.anthropicModel;
        c.ai.openaiKey      = aiOpenAIKey?.text                  ?? c.ai.openaiKey;
        c.ai.openaiModel    = aiOpenAIModel?.text                ?? c.ai.openaiModel;
        c.ai.blockThreshold = aiBlockThresh?.pos                 ?? c.ai.blockThreshold;
        c.ai.warnThreshold  = aiWarnThresh?.pos                  ?? c.ai.warnThreshold;

        c.terminal.autoBlock   = termAutoBlock?.selected         ?? c.terminal.autoBlock;
        c.terminal.githubToken = termGithubToken?.text           ?? c.terminal.githubToken;
        c.terminal.trustedTaps = splitLines(termTrustedTaps?.text ?? "");

        c.updates.blockUnknownDomains = updBlockUnknown?.selected ?? c.updates.blockUnknownDomains;
        c.updates.trustedDomains      = splitLines(updTrustedDomains?.text ?? "");

        c.extensions.autoDisable          = extAutoDisable?.selected    ?? c.extensions.autoDisable;
        c.extensions.maxPermissions       = Std.int(extMaxPerms?.pos    ?? c.extensions.maxPermissions);
        c.extensions.dangerousPermissions = splitLines(extDangerousPerms?.text ?? "");

        c.network.logConnections = netLogConnections?.selected ?? c.network.logConnections;
        c.network.ignoredApps    = splitLines(netIgnoredApps?.text ?? "");

        Config.save();

        if (lblSaveStatus != null) {
            lblSaveStatus.text = "✓  Saved";
            if (saveTimer != null) saveTimer.stop();
            saveTimer = haxe.Timer.delay(() -> {
                if (lblSaveStatus != null) lblSaveStatus.text = "";
            }, 2500);
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────

    static function splitLines(s:String):Array<String> {
        return s.split("\n").map(l -> l.trim()).filter(l -> l.length > 0);
    }

    static function fmtF(v:Float):String {
        return Std.string(Math.round(v * 100) / 100);
    }

    static function setText(tf:TextField, v:String) {
        if (tf != null) tf.text = v;
    }

    static function setSlider(sl:Slider, v:Float, lbl:Label) {
        if (sl  != null) sl.pos   = v;
        if (lbl != null) lbl.text = fmtF(v);
    }

    static function setDropdown(dd:DropDown, value:String) {
        if (dd == null) return;
        for (i in 0...dd.dataSource.size) {
            if (dd.dataSource.get(i).value == value) {
                dd.selectedIndex = i;
                return;
            }
        }
    }
}
