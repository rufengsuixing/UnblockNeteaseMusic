var sni2 = require('./sni-reader');
var dns = require('dns');
const hook = require('./hook');
var AsyncCache = require('./async-cache');
const net = require('net')

var port = process.env.PORT || 443;
if (process.env.DNS) {
	dns.setServers(process.env.DNS.split(','));
}
var shutdownGrace = process.env.SHUTDOWN_GRACE || 5000;


var dnsCache = new AsyncCache({
	max: 1000,
	maxAge: process.env.DNS_CACHE || 3600 * 1000,
	load: function (key, cb) {
		console.log('Looking up AAAA', key);
		dns.resolve6(key, cb);
	}
});

function initSession(serverSocket, sniName) {
	dnsCache.get(sniName, function (err, addresses) {
		if (err) {
			serverSocket.end();
			console.log(serverSocket.remoteAddress, sniName, 'resolve', err ? err.code : null);
			return;
		}
		
		var ip = addresses[0];
		var clientSocket = net.connect({port: 443, type: 'tcp6', host: ip});
		console.log(serverSocket.remoteAddress, sniName, 'connecting', addresses);
		
		clientSocket.on('connect', function() {
			serverSocket.pipe(clientSocket).pipe(serverSocket);
			console.log(serverSocket.remoteAddress, sniName, 'connected', ip);
		});
		clientSocket.on('error', function(err) {
			console.log(sniName, 'Client socket reported', err.code);
			serverSocket.end();
		})
		serverSocket.on('error', function(err) {
			console.log(serverSocket.remoteAddress, 'Server socket reported', err.code);
			clientSocket.end();
		})
	});
};

function interrupt() {
	server.close();
	server.getConnections(function (err, count) {
		if (!err && count) {
			console.error('Waiting for clients to disconnect. Grace', shutdownGrace);
			setTimeout(function() {
				process.exit();
			}, shutdownGrace);
		} else if (err) {
			console.fatal('Error while receiving interrupt! Attempt to bail, no grace.', err);
			process.exit();
		}
	});
};
var http = require('http'),
    https = require('https'),
    inherits = require('util').inherits,
    httpSocketHandler = http._connectionListener;

var isOldNode = /^v0\.10\./.test(process.version);

function Server(tlsconfig, requestListener) {
  if (!(this instanceof Server))
    return new Server(tlsconfig, requestListener);

  if (typeof tlsconfig === 'function') {
    requestListener = tlsconfig;
    tlsconfig = undefined;
  }

  if (typeof tlsconfig === 'object') {
    this.removeAllListeners('connection');

    https.Server.call(this, tlsconfig, requestListener);

    // capture https socket handler, it's not exported like http's socket
    // handler
    var connev = this._events.connection;
    if (typeof connev === 'function')
      this._tlsHandler = connev;
    else
      this._tlsHandler = connev[connev.length - 1];
    this.removeListener('connection', this._tlsHandler);

    this._connListener = connectionListener;
    this.on('connection', connectionListener);

    // copy from http.Server
    this.timeout = 2 * 60 * 1000;
    this.allowHalfOpen = true;
    this.httpAllowHalfOpen = false;
  } else
    http.Server.call(this, requestListener);
}
inherits(Server, https.Server);

Server.prototype.setTimeout = function(msecs, callback) {
  this.timeout = msecs;
  if (callback)
    this.on('timeout', callback);
};

Server.prototype.__httpSocketHandler = httpSocketHandler;

function onError(err) {}

var connectionListener;
if (isOldNode) {
  connectionListener = function(socket) {
    var self = this;

    // Ignore any errors before detection
    socket.on('error', onError);

    socket.ondata = function(d, start, end) {
      var firstByte = d[start];
      socket.removeListener('error', onError);
      if (firstByte < 32 || firstByte >= 127) {
        // tls/ssl
        socket.ondata = null;
        self._tlsHandler(socket);
        socket.push(d.slice(start, end));
      } else {
        self.__httpSocketHandler(socket);
        socket.ondata(d, start, end);
      }
    };
  };
} else {
  connectionListener = function(socket) {
    var self = this;
    var data;
    data = socket.read(1);
    if (data === null) {
      socket.removeListener('error', onError);
      socket.on('error', onError);

      socket.once('readable', function() {
        self._connListener(socket);
      });
    } else {
      socket.removeListener('error', onError);

      var firstByte = data[0];
      socket.unshift(data);
      if (firstByte < 32 || firstByte >= 127) {
        // tls/ssl
		var sniret=sni2(socket);
		var err=sniret.err;
		var sniName=sniret.sn;
		if (err) {
			console.log(err);
			socket.end();
		} else if (sniName) {
			console.log(socket.remoteAddress, sniName);
			if (hook.target.host.includes(sniName)) {
				this._tlsHandler(socket);
			}
			socket.on('error', function(err){
				if (err.code == 'EPIPE') {
					console.log(socket.remoteAddress, 'Client disconnected before the pipe was connected.');
				} else {
					console.log(err);
				}
				socket.end();
			});
			initSession(socket, sniName);
		} else {
			console.log(socket.remoteAddress, '(none)');
			socket.end();
		}
      } else
        this.__httpSocketHandler(socket);
    }
  };
}

exports.Server = Server;

exports.createServer = function(tlsconfig, requestListener) {
  return new Server(tlsconfig, requestListener);
};
