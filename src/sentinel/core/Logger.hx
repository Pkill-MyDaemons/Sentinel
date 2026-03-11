package sentinel.core;

using StringTools;

import sys.io.File;
import sys.FileSystem;
import Date;

enum LogLevel { DEBUG; INFO; WARN; ERROR; CRITICAL; }

class Logger {

    static var logFile:sys.io.FileOutput;
    static var minLevel:LogLevel = INFO;

    public static function init(?level:LogLevel) {
        if (level != null) minLevel = level;
        var home = Sys.getEnv("HOME");
        if (home == null) home = "/tmp";
        var dir = '$home/.sentinel/logs';
        if (!FileSystem.exists(dir)) FileSystem.createDirectory(dir);
        var fname = '$dir/sentinel-${DateTools.format(Date.now(), "%Y%m%d")}.log';
        logFile = File.append(fname, false);
        info("=== Sentinel log session started ===");
    }

    public static function debug(msg:String) log(DEBUG, msg);
    public static function info(msg:String)  log(INFO,  msg);
    public static function warn(msg:String)  log(WARN,  msg);
    public static function error(msg:String) log(ERROR, msg);
    public static function critical(msg:String) log(CRITICAL, msg);

    static function log(level:LogLevel, msg:String) {
        if (!shouldLog(level)) return;
        var ts = DateTools.format(Date.now(), "%H:%M:%S");
        var label = levelLabel(level);
        var line = '[$ts][$label] $msg';
        Sys.println(line);
        if (logFile != null) {
            logFile.writeString(line + "\n");
            logFile.flush();
        }
    }

    static function shouldLog(level:LogLevel):Bool {
        return Type.enumIndex(level) >= Type.enumIndex(minLevel);
    }

    static function levelLabel(l:LogLevel):String {
        return switch l {
            case DEBUG:    "DEBUG";
            case INFO:     "INFO ";
            case WARN:     "WARN ";
            case ERROR:    "ERROR";
            case CRITICAL: "CRIT ";
        };
    }
}
