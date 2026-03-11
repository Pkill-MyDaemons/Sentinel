package sentinel.app;

using StringTools;
using Lambda;

import haxe.ui.ComponentBuilder;
import haxe.ui.containers.VBox;
import haxe.ui.containers.HBox;
import haxe.ui.containers.ListView;
import haxe.ui.components.Button;
import haxe.ui.components.Label;
import haxe.ui.components.TextArea;
import haxe.ui.core.Component;
import haxe.ui.events.UIEvent;
import haxe.Json;
import sys.io.File;
import sys.FileSystem;
import sentinel.gui.Alert;

/**
 * AlertsView — populates the Alerts tab with a list + detail panel.
 *
 * Correct HaxeUI API (v1.7):
 *   - component.hidden = true/false  (NOT .visible)
 *   - button.addClass("name")        (NOT addStyleName)
 *   - button.removeClass("name")     (NOT removeStyleName)
 *   - TextArea has no editable field; use disabled = true for read-only
 *   - ComponentBuilder.fromFile      (buildComponent is deprecated)
 */
class AlertsView {

    static final FILTER_IDS = [
        "btn-filter-all"        => "all",
        "btn-filter-new"        => "new",
        "btn-filter-terminal"   => "terminal",
        "btn-filter-updates"    => "updates",
        "btn-filter-extensions" => "extensions",
        "btn-filter-network"    => "network",
    ];

    var tabRoot:VBox;
    var root:Component;
    var listView:ListView;
    var alerts:Array<Alert>   = [];
    var filtered:Array<Alert> = [];
    var selectedId:Int = -1;
    var filterSource:String = "all";
    var alertsPath:String;

    // Detail refs
    var detailEmpty:Label;
    var detailContent:VBox;
    var detailTitle:Label;
    var detailRisk:Label;
    var detailSource:Label;
    var detailTime:Label;
    var detailBody:TextArea;
    var detailStatus:Label;
    var btnReviewed:Button;
    var btnDismiss:Button;

    public function new(appRoot:Component) {
        alertsPath = (Sys.getEnv("HOME") ?? "/tmp") + "/.sentinel/alerts.json";

        // Find the alerts tab container
        tabRoot = appRoot.findComponent("tab-alerts", VBox, true);

        // Build the alerts panel and attach it
        root = ComponentBuilder.fromFile("assets/alerts-view.xml");
        tabRoot.addComponent(root);

        cacheRefs();
        bindEvents();
    }

    public function newCount():Int {
        return alerts.filter(a -> a.status == "new").length;
    }

    public function reload() {
        loadAlerts();
        applyFilter();
        renderList();
        if (selectedId >= 0) {
            var a = alerts.find(x -> x.id == selectedId);
            if (a != null) showDetail(a) else hideDetail();
        }
    }

    // ── Private ─────────────────────────────────────────────────────

    function cacheRefs() {
        listView      = root.findComponent("alerts-list",    ListView, true);
        detailEmpty   = root.findComponent("detail-empty",   Label,    true);
        detailContent = root.findComponent("detail-content", VBox,     true);
        detailTitle   = root.findComponent("detail-title",   Label,    true);
        detailRisk    = root.findComponent("detail-risk",    Label,    true);
        detailSource  = root.findComponent("detail-source",  Label,    true);
        detailTime    = root.findComponent("detail-time",    Label,    true);
        detailBody    = root.findComponent("detail-body",    TextArea, true);
        detailStatus  = root.findComponent("detail-status",  Label,    true);
        btnReviewed   = root.findComponent("btn-reviewed",   Button,   true);
        btnDismiss    = root.findComponent("btn-dismiss",    Button,   true);
    }

    function bindEvents() {
        for (btnId => src in FILTER_IDS) {
            var btn = root.findComponent(btnId, Button, true);
            if (btn == null) continue;
            var cap = src;
            btn.onClick = (_) -> {
                filterSource = cap;
                for (id in FILTER_IDS.keys()) {
                    var fb = root.findComponent(id, Button, true);
                    if (fb != null) fb.removeClass("active-filter");
                }
                btn.addClass("active-filter");
                applyFilter();
                renderList();
            };
        }

        var btnMarkAll = root.findComponent("btn-mark-all", Button, true);
        if (btnMarkAll != null) btnMarkAll.onClick = (_) -> markAllReviewed();

        var btnRefresh = root.findComponent("btn-refresh", Button, true);
        if (btnRefresh != null) btnRefresh.onClick = (_) -> reload();

        if (listView != null) {
            listView.onChange = (_) -> {
                var idx = listView.selectedIndex;
                if (idx >= 0 && idx < filtered.length)
                    showDetail(filtered[idx]);
            };
        }

        if (btnReviewed != null) btnReviewed.onClick = (_) -> {
            if (selectedId >= 0) mutateAlert(selectedId, "reviewed");
        };
        if (btnDismiss != null) btnDismiss.onClick = (_) -> {
            if (selectedId >= 0) {
                mutateAlert(selectedId, "dismissed");
                selectedId = -1;
                hideDetail();
            }
        };
    }

    function loadAlerts() {
        try {
            if (!FileSystem.exists(alertsPath)) { alerts = []; return; }
            var data = Json.parse(File.getContent(alertsPath));
            alerts = data.alerts;
        } catch (_:Dynamic) { alerts = []; }
    }

    function applyFilter() {
        filtered = switch filterSource {
            case "all":  alerts.filter(a -> a.status != "dismissed");
            case "new":  alerts.filter(a -> a.status == "new");
            default:     alerts.filter(a -> a.status != "dismissed"
                             && a.source.toLowerCase() == filterSource);
        };
    }

    function renderList() {
        if (listView == null) return;
        listView.dataSource.clear();
        for (a in filtered) {
            var prefix  = a.status == "new" ? "● " : "  ";
            var riskUp  = a.risk.toUpperCase();
            listView.dataSource.add({
                text:    '$prefix[$riskUp]  ${a.title}',
                subtext: '${a.source}  ·  ${a.timestamp}',
            });
        }
    }

    function showDetail(a:Alert) {
        selectedId = a.id;
        if (detailEmpty   != null) detailEmpty.hidden   = true;
        if (detailContent != null) detailContent.hidden = false;
        if (detailTitle   != null) detailTitle.text     = a.title;
        if (detailRisk    != null) detailRisk.text      = a.risk.toUpperCase();
        if (detailSource  != null) detailSource.text    = a.source;
        if (detailTime    != null) detailTime.text      = a.timestamp;
        if (detailBody    != null) detailBody.text      = a.detail != null ? a.detail : "";
        if (detailStatus  != null) detailStatus.text    = a.status;
    }

    function hideDetail() {
        if (detailEmpty   != null) detailEmpty.hidden   = false;
        if (detailContent != null) detailContent.hidden = true;
    }

    function mutateAlert(id:Int, newStatus:String) {
        try {
            if (!FileSystem.exists(alertsPath)) return;
            var data = Json.parse(File.getContent(alertsPath));
            var arr:Array<Alert> = data.alerts;
            for (a in arr) if (a.id == id) { a.status = newStatus; break; }
            File.saveContent(alertsPath, Json.stringify(data, null, "  "));
        } catch (_:Dynamic) {}
        reload();
    }

    function markAllReviewed() {
        try {
            if (!FileSystem.exists(alertsPath)) return;
            var data = Json.parse(File.getContent(alertsPath));
            var arr:Array<Alert> = data.alerts;
            for (a in arr) if (a.status == "new") a.status = "reviewed";
            File.saveContent(alertsPath, Json.stringify(data, null, "  "));
        } catch (_:Dynamic) {}
        reload();
    }
}
