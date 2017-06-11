/* globals setImmediate */
const EventEmitter = require('events').EventEmitter
const util = require('util')
const methodman = require('methodman')
const SimplePeer = require('simple-peer')
const signalExchange = require('signal-exchange')
const sodi = require('sodi')
const getRoom = require('room-exchange')
// const = require('lodash') // Development Only
const _ =
  { extend: require('lodash.assignin'),
    keys: require('lodash.keys'),
    without: require('lodash.without'),
    uniq: require('lodash.uniq'),
    values: require('lodash.values')
  }

const noopCallback = (err) => { if (err) console.error(err) }

function setupPeer (swarm, peer) {
  function emit () {
    swarm.emit.apply(swarm, arguments)
    peer.emit.apply(peer, arguments)
  }

  let meth = methodman(peer)
  meth.commands(swarm.rpc, 'init')
  meth.on('commands:init', remote => {
    remote.publicKey = peer.publicKey
    swarm.remotes[peer.publicKey] = remote
    emit('remote', remote)
  })
  meth.on('commands', (remote, id) => {
    emit('commands', remote, id)
    emit(`commands:${id}`, remote)
  })
  peer.createStream = (id) => meth.stream(id)
  meth.on('stream', (stream, id) => {
    // TODO: Relay streams.
    emit('substream', stream, id)
    emit(`substream:${id}`, stream)
  })
  peer.meth = meth
}

// Default RPC methods
function RPC (swarm) {
  // This can't be a class-like object because dnode
  // requires that it be a regular hash object.
  let rpc = {}
  rpc.ping = cb => cb(null)
  rpc.getNetwork = cb => cb(null, swarm.network)

  // TODO: verify the request came from this public key
  rpc.connect = (proxyKey, pubKey, cb) => {
    if (pubKey > swarm.publicKey) {
      return cb(new Error('Cannot connect to a larger pub key.'))
    }
    if (swarm.peers[pubKey]) {
      return cb(new Error('Already connecting'))
    }
    if (pubKey === swarm.publicKey) throw new Error('wtf2')
    let _opts = _.extend({trickle: false}, {initiator: true}, swarm.opts)
    let peer = new SimplePeer(_opts)
    peer.on('signal', signal => {
      signal = swarm.encrypt(JSON.stringify(signal), pubKey)
      signal.box = signal.box.toString('hex')
      signal.nonce = signal.nonce.toString('hex')
      swarm.getRemote(proxyKey).proxySignal(pubKey, swarm.publicKey, signal, cb)
    })
    peer._created = Date.now()
    peer.once('connect', createOnConnect(swarm, peer, pubKey))
    swarm.peers[pubKey] = peer
  }

  rpc.inform = (toPublicKey, fromPublicKey, cb) => {
    if (!swarm.getRemote(toPublicKey)) {
      swarm.once('remote', () => rpc.inform(toPublicKey, fromPublicKey, cb))
    } else {
      swarm.getRemote(toPublicKey).connect(swarm.publicKey, fromPublicKey, cb)
    }
  }

  rpc.signal = (proxyKey, pubKey, sig, cb) => {
    // TODO: Use proxied RPC to force the other side to initiate.
    // this way it can deny the request if it is mid-stream.
    sig = swarm.decrypt(new Buffer(sig.box, 'hex'), new Buffer(sig.nonce, 'hex'), pubKey)
    sig = JSON.parse(sig)

    if (sig.type === 'offer' && !swarm.peers[pubKey]) {
      let _opts = _.extend({trickle: false}, swarm.opts)
      let peer = new SimplePeer(_opts)
      peer.on('signal', signal => {
        signal = swarm.encrypt(JSON.stringify(signal), pubKey)
        signal.box = signal.box.toString('hex')
        signal.nonce = signal.nonce.toString('hex')
        swarm.getRemote(proxyKey).proxySignal(pubKey, swarm.publicKey, signal, cb)
      })
      peer._created = Date.now()
      peer.once('connect', createOnConnect(swarm, peer, pubKey))
      swarm.peers[pubKey] = peer
    }
    swarm.peers[pubKey].signal(sig)
  }
  rpc.proxySignal = (toPubKey, fromPubKey, sig, cb) => {
    if (!cb) cb = () => {}
    swarm.getRemote(toPubKey).signal(swarm.publicKey, fromPubKey, sig, cb)
  }
  return rpc
}

function Swarm (opts) {
  const keypair = opts.keypair || sodi.generate()
  const crypto = sodi(keypair)
  this.publicKey = crypto.public

  this.rpc = RPC(this)
  this.maxDelay = 1000

  this.opts = opts || {}
  this.dnodes = {}
  this.remotes = {}
  this.peers = {}
  this.network = {}
  this.relays = {}

  this.on('peer', (peer) => {
    this.network[peer.publicKey] = null
  })

  this.on('remote', remote => {
    this.ping(remote.publicKey, (err, delay) => {
      if (err) return console.error('cannot ping', err)
    })
    let checkNetwork = () => {
      remote.getNetwork((err, net) => {
        if (err) return console.error(err)
        let netkeys = _.keys(net)
        let newpeers = _.without(netkeys, this.publicKey, ..._.keys(this.peers))
        newpeers.forEach(pubKey => {
          if (pubKey === this.publicKey) throw new Error('wtf1')
          if (pubKey < this.publicKey) {
            // My key is larger, I need to be the initiator.
            let _opts = _.extend({}, {initiator: true}, this.opts)
            let peer = new SimplePeer(_opts)
            peer.nonce = // big ass random number, to be compared later.
            peer.on('signal', signal => {
              signal = this.encrypt(JSON.stringify(signal), pubKey)
              signal.box = signal.box.toString('hex')
              signal.nonce = signal.nonce.toString('hex')
              remote.proxySignal(pubKey, this.publicKey, signal)
            })
            peer._created = Date.now()
            peer.once('connect', createOnConnect(this, peer, pubKey))
            this.peers[pubKey] = peer
            if (err) return console.error(pubKey.slice(0, 9), err)
          } else {
            // Their key is larger, they need to know about me.
            remote.inform(pubKey, this.publicKey, (err) => {
              if (err) {
                // We don't need to do anything, this likely errored
                // because it was already connecting.
              }
            })
          }
        })
      })
      remote._timeout = setTimeout(checkNetwork, 1000 * 30)
    }
    checkNetwork()
  })
  window.SimplePeer = SimplePeer

  let onSignal = signal => {
    if (this.peers[signal.from]) {
      // Response for initiated request.
      this.peers[signal.from].signal(signal.offer)
    } else {
      let _opts = _.extend({}, {trickle: false}, this.opts)
      let peer = new SimplePeer(_opts)
      peer.publicKey = signal.from
      peer.once('signal', offer => {
        this.sendSignal(signal.from, offer)
      })
      peer.signal(signal.offer)
      peer.once('connect', createOnConnect(this, peer, signal.from))
      this.peers[signal.from] = peer
    }
  }

  let sendSignal = signalExchange(keypair, onSignal)

  this.sendSignal = sendSignal
  this._callQueue = []
  sendSignal.onReady = () => {
    this._ready = true
    this._callQueue.forEach(args => this.call(...args))
    this._callQueue = []
    this.emit('ready')
  }

  this.encrypt = crypto.encrypt
  this.decrypt = crypto.decrypt
  this.sign = crypto.sign

  this.joinRoom = (host, room) => {
    this.joinRoom = () => { throw new Error('Already in room.') }
    // TODO: allow roomHost option to override host
    getRoom(room, keypair, (err, data) => {
      if (err) return console.error(err)
      let keys = data.keys
      keys = _.uniq(keys)
      while (keys.indexOf(this.publicKey) !== -1) {
        keys.splice(keys.indexOf(this.publicKey), 1)
      }
      sendSignal.ping(keys, (key) => {
        this.call(key)
      })
    })
  }
}
util.inherits(Swarm, EventEmitter)
Swarm.prototype.call = function (pubKey, cb) {
  if (this.peers[pubKey]) return

  if (!cb) cb = noopCallback
  if (!this._ready) return this._callQueue.push([pubKey, cb])

  var _opts = _.extend({initiator: true, trickle: false}, this.opts)
  var peer = new SimplePeer(_opts)
  peer.publicKey = pubKey
  peer.once('signal', offer => {
    peer.__signal = offer
    this.sendSignal(pubKey, offer)
  })
  peer.on('connect', createOnConnect(this, peer, pubKey, cb))
  this.peers[pubKey] = peer
}
Swarm.prototype.ping = function (publicKey, cb) {
  let start = Date.now()
  this.getRemote(publicKey).ping(() => {
    let delay = Date.now() - start
    this.network[publicKey] = delay
    if (cb) cb(null, delay)
  })
}
Swarm.prototype.getRemote = function (publicKey) {
  return this.remotes[publicKey]
}
Swarm.prototype.activeKeys = function (cb) {
  // TODO: parse through the peers in the db as well.
  cb(null, Object.keys(this.peers))
}
Swarm.prototype.destroy = function () {
  _.values(this.peers).forEach(p => p.destroy())
}

if (process.browser) {
  window.Swarm = Swarm
}
module.exports = opts => new Swarm(opts)

function createOnConnect (swarm, peer, pubKey, cb) {
  function onclose () {
    delete swarm.peers[pubKey]
    delete swarm.remotes[pubKey]
    delete swarm.network[pubKey]
    swarm.emit('disconnect', pubKey, peer)
  }
  peer.on('error', onclose)
  peer.once('close', onclose)
  peer.once('stream', stream => { peer.__stream = stream })
  peer.once('stream', stream => {
    stream.peer = peer
    swarm.emit('stream', stream)
  })

  function _ret () {
    if (cb) cb(null, peer)
    peer.publicKey = pubKey
    // swarm.peers[pubKey] = peer
    setupPeer(swarm, peer)
    swarm.emit('peer', peer)
    if (peer.__stream) peer.emit('stream', peer.__stream)
  }
  return _ret
}
