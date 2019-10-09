var sni2 = require('./sni-reader');
var dns = require('dns');

var AsyncCache = require('./async-cache');

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
		dns.resolve(key, cb);
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
		console.log(ip)
		var port=443
		if (hook.target.host.includes(sniName)){
			
			ip="127.0.0.1"
			port=5201
		}
		var clientSocket = net.connect({port: port, type: 'tcp6', host: ip});
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
const fs = require('fs')
const net = require('net')
const path = require('path')
const parse = require('url').parse

const sni = require('./sni')
const hook = require('./hook')
const request = require('./request')

const proxy = {
	core: {
		mitm: (req, res) => {
			if(req.url == '/proxy.pac'){
				let url = parse('http://' + req.headers.host)
				res.writeHead(200, {'Content-Type': 'application/x-ns-proxy-autoconfig'})
				res.end(`
					function FindProxyForURL(url, host) {
						if (${hook.target.host.map(host => (`host == '${host}'`)).join(' || ')}) {
							return 'PROXY ${url.hostname}:${url.port || 80}'
						}
						return 'DIRECT'
					}
				`)
			}
			else{
				const ctx = {res, req}
				Promise.resolve()
				.then(() => proxy.protect(ctx))
				.then(() => proxy.authenticate(ctx))
				.then(() => hook.request.before(ctx))
				.then(() => proxy.filter(ctx))
				.then(() => proxy.log(ctx))
				.then(() => proxy.mitm.request(ctx))
				.then(() => hook.request.after(ctx))
				.then(() => proxy.mitm.response(ctx))
				.catch(() => proxy.mitm.close(ctx))
			}
		},
		tunnel: (req, socket, head) => {
			const ctx = {req, socket, head}
			Promise.resolve()
			.then(() => proxy.protect(ctx))
			.then(() => proxy.authenticate(ctx))
			.then(() => hook.connect.before(ctx))
			.then(() => proxy.filter(ctx))
			.then(() => proxy.log(ctx))
			.then(() => proxy.tunnel.connect(ctx))
			.then(() => proxy.tunnel.dock(ctx))
			.then(() => hook.negotiate.before(ctx))
			.then(() => proxy.tunnel.pipe(ctx))
			.catch(() => proxy.tunnel.close(ctx))
		}
	},
	abort: (socket, from) => {
		// console.log('call abort', from)
		if(socket) socket.end()
		if(socket && !socket.destroyed) socket.destroy()
	},
	protect: ctx => {
		const req = ctx.req
		const res = ctx.res
		const socket = ctx.socket
		if(req) req.on('error', () => proxy.abort(req.socket, 'req'))
		if(res) res.on('error', () => proxy.abort(res.socket, 'res'))
		if(socket) socket.on('error', () => proxy.abort(socket, 'socket'))
	},
	log: ctx => {
		const mark = {close: '|', blank: '-', proxy: '>'}[ctx.decision] || '>'
		if(ctx.socket)
			console.log('TUNNEL', mark, ctx.req.url)
		else
			console.log('MITM', mark, parse(ctx.req.url).host, ctx.req.socket.encrypted ? '(ssl)' : '')
	},
	authenticate: ctx => {
		const req = ctx.req
		const res = ctx.res
		const socket = ctx.socket
		let credential = Buffer.from((req.headers['proxy-authorization'] || '').split(/\s+/).pop() || '', 'base64').toString()
		if('proxy-authorization' in req.headers) delete req.headers['proxy-authorization']
		if(server.authentication && credential != server.authentication && (socket || req.url.startsWith('http://'))){
			if(socket)
				socket.write('HTTP/1.1 407 Proxy Auth Required\r\nProxy-Authenticate: Basic realm="realm"\r\n\r\n')
			else
				res.writeHead(407, {'proxy-authenticate': 'Basic realm="realm"'})
			return Promise.reject(ctx.error = 'authenticate')
		}
	},
	filter: ctx => {
		const url = parse((ctx.socket ? 'https://' : '') + ctx.req.url)
		const match = pattern => url.href.search(new RegExp(pattern, 'g')) != -1
		if(!(ctx.decision || ctx.req.local)){
			try{
				let allow = server.whitelist.some(match)
				let deny = server.blacklist.some(match)
				// console.log('allow', allow, 'deny', deny)
				if(!allow && deny){
					return Promise.reject(ctx.error = 'filter')
				}
			}
			catch(error){
				ctx.error = error
			}
		}
	},
	mitm: {
		request: ctx => new Promise((resolve, reject) => {
			if(ctx.decision === 'close') return reject(ctx.error = ctx.decision)
			const req = ctx.req
			const url = parse(req.url)
			const options = request.configure(req.method, url, req.headers)
			ctx.proxyReq = request.create(url)(options)
			.on('response', proxyRes => resolve(ctx.proxyRes = proxyRes))
			.on('error', error => reject(ctx.error = error))
			req.readable ? req.pipe(ctx.proxyReq) : ctx.proxyReq.end(req.body)
		}),
		response: ctx => {
			const res = ctx.res
			const proxyRes = ctx.proxyRes.on('error', () => proxy.abort(ctx.proxyRes.socket, 'proxyRes'))
			res.writeHead(proxyRes.statusCode, proxyRes.headers)
			proxyRes.readable ? proxyRes.pipe(res) : res.end(proxyRes.body)
		},
		close: ctx => {
			proxy.abort(ctx.res.socket, 'mitm')
		}
	},
	tunnel: {
		connect: ctx => new Promise((resolve, reject) => {
			if(ctx.decision === 'close') return reject(ctx.error = ctx.decision)
			const req = ctx.req
			const url = parse('https://' + req.url)
			if(global.proxy && !req.local){
				const options = request.configure(req.method, url, req.headers)
				request.create(proxy)(options)
				.on('connect', (_, proxySocket) => resolve(ctx.proxySocket = proxySocket))
				.on('error', error => reject(ctx.error = error))
				.end()
			}
			else{
				const proxySocket = net.connect(url.port || 443, request.translate(url.hostname))
				.on('connect', () => resolve(ctx.proxySocket = proxySocket))
				.on('error', error => reject(ctx.error = error))
			}
		}),
		dock: ctx => new Promise(resolve => {
			const req = ctx.req
			const socket = ctx.socket
			socket
			.once('data', data => resolve(ctx.head = Buffer.concat([ctx.head, data])))
			.write(`HTTP/${req.httpVersion} 200 Connection established\r\n\r\n`)
		}).then(data => ctx.socket.sni = sni(data)).catch(() => {}),
		pipe: ctx => {
			if(ctx.decision === 'blank') return Promise.reject(ctx.error = ctx.decision)
			const head = ctx.head
			const socket = ctx.socket
			const proxySocket = ctx.proxySocket.on('error', () => proxy.abort(ctx.proxySocket, 'proxySocket'))
			proxySocket.write(head)
			socket.pipe(proxySocket)
			proxySocket.pipe(socket)
		},
		close: ctx => {
			proxy.abort(ctx.socket, 'tunnel')
		}
	}
}

const options = {
	key: fs.readFileSync(path.join(__dirname, 'server.key')),
	cert: fs.readFileSync(path.join(__dirname, 'server.crt'))
}

const server = {
	http: require('http').createServer().on('request', proxy.core.mitm).on('connect', proxy.core.tunnel),
	https: require('https').createServer(options).on('request', proxy.core.mitm).on('connect', proxy.core.tunnel),
	redirect:net.createServer(function (serverSocket) {
		sni2(serverSocket, function(err, sniName) {
			if (err) {
				console.log(err);
				serverSocket.end();
			} else if (sniName) {
				console.log(serverSocket.remoteAddress, sniName);
				serverSocket.on('error', function(err){
					if (err.code == 'EPIPE') {
						console.log(serverSocket.remoteAddress, 'Client disconnected before the pipe was connected.');
					} else {
						console.log(err);
					}
					serverSocket.end();
				});
				initSession(serverSocket, sniName);
			} else {
				console.log(serverSocket.remoteAddress, '(none)');
				serverSocket.end();
			}
		});
	})
}

server.whitelist = []
server.blacklist = ['//127\.\d+\.\d+\.\d+', '//localhost']
server.authentication = null

module.exports = server