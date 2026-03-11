package sentinel.gui;

/**
 * AlertStore — subscribes to EventBus, keeps a ring buffer of alerts,
 * and persists them to ~/.sentinel/alerts.json so the native GUI app
 * can read them without needing a live IPC connection.
 */
typedef Alert = {
    var id:Int;
    var timestamp:String;
    var source:String;
    var risk:String;
    var title:String;
    var detail:String;
    var status:String; // "new" | "reviewed" | "dismissed"
}
