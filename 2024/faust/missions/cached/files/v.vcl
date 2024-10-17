vcl 4.1;

import std;

backend api {
	.host = "api";
	.port = "5000";
}

backend default {
	.host = "frontend";
	.port = "3000";
}

sub vcl_recv {
    if (req.http.upgrade ~ "(?i)websocket") {
        return (pipe);
    }
	if(req.url ~ "/api") {
		set req.backend_hint = api;
	}
	if(req.url ~ "/imgs") {
		set req.backend_hint = api;
	}
	if (req.method != "GET" && req.method != "HEAD") {
		return (pass);
	}
	if (req.url ~ "/imgs") {
		return (hash);
	}
	if (req.url ~ "/auth" || req.url ~ "/private") {
		return (pass);
	}
	
	return (pass);
}

sub vcl_pipe {
    if (req.http.upgrade) {
        set bereq.http.upgrade = req.http.upgrade;
        set bereq.http.connection = req.http.connection;
    }
}

sub vcl_hash {
	hash_data(req.url);
	if (req.http.host) {
		hash_data(req.http.host);
	} else {
		hash_data(server.ip);
	}
	return (lookup);
}

sub vcl_backend_response {
	unset beresp.http.Vary;
	if (bereq.uncacheable) {
		return (deliver);
	} else if (beresp.ttl <= 0s ||
	  /*beresp.http.Set-Cookie ||*/
	  beresp.http.Surrogate-control ~ "(?i)no-store" ||
	  /*(!beresp.http.Surrogate-Control &&
		beresp.http.Cache-Control ~ "(?i:no-cache|no-store|private)") ||*/
	  beresp.http.Vary == "*") {
		set beresp.ttl = 360s;
		set beresp.uncacheable = true;
	}
	return (deliver);
}

sub vcl_deliver {
	unset resp.http.Vary;
	unset resp.http.Via;
	unset resp.http.X-Varnish;
	unset resp.http.Age;
	unset resp.http.Server;
}
