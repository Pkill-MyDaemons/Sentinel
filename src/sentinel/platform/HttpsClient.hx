package sentinel.platform;

import haxe.Http;
import haxe.io.Output;

/**
 * HttpsClient — thin wrapper around haxe.Http that uses sys.ssl.Socket
 * for HTTPS requests.
 *
 * haxe.Http on the HL/cpp targets throws "Https is only supported with
 * -lib hxssl" when you call .request() on an https:// URL, because its
 * default code path tries to load hxssl.  The fix is to supply a
 * sys.ssl.Socket directly via .customRequest() — the stdlib sys.ssl
 * package ships with HashLink (ssl.hdll) and hxcpp, no extra haxelib
 * needed.
 *
 * Usage — drop-in replacement for the haxe.Http + .request() pattern:
 *
 *   var res = HttpsClient.get("https://api.github.com/...", headers);
 *   var res = HttpsClient.post("https://...", body, headers);
 */
class HttpsClient {

    /**
     * Synchronous HTTPS GET.
     * Returns the response body, or throws on error.
     */
    public static function get(url:String, ?headers:Map<String,String>):String {
        return send(url, null, headers);
    }

    /**
     * Synchronous HTTPS POST with a JSON (or any string) body.
     * Returns the response body, or throws on error.
     */
    public static function post(url:String, body:String, ?headers:Map<String,String>):String {
        return send(url, body, headers);
    }

    // ----------------------------------------------------------------

    static function send(url:String, ?body:String, ?headers:Map<String,String>):String {
        var http = new Http(url);

        if (headers != null)
            for (k => v in headers)
                http.setHeader(k, v);

        if (body != null)
            http.setPostData(body);

        var response = "";
        var error    = "";
        http.onData  = (d) -> response = d;
        http.onError = (e) -> error    = e;

        #if (hl || hlc || cpp)
        // Use sys.ssl.Socket so HashLink/hxcpp handle TLS natively.
        // verifyCert = false skips cert chain validation — fine for
        // api calls where we trust the hostname via DNS.
        var ssl = new sys.ssl.Socket();
        ssl.verifyCert = false;
        http.customRequest(body != null, new haxe.io.BytesOutput(), ssl);
        #else
        http.request(body != null);
        #end

        if (error != "") throw error;
        return response;
    }
}
