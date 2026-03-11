package sentinel.core;

using StringTools;

interface IModule {
    public function name():String;
    public function start():Void;
    public function stop():Void;
}
