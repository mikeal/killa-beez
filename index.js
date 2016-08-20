const PouchDB = require('pouchdb')
const multiplex = require('multiplex')
const crypto = require('crypto')
const dnode = require('dnode')
const duplexify = require('duplexify')
const EventEmitter = require('events').EventEmitter
const util = require('util')
const SimplePeer = require('simple-peer')
const extend = require('lodash.assign')
const jsonstream = require('jsonstream2')
const through2 = require('through2')
const signalExchange = require('signal-exchange')

const noopCallback = (err) => { if (err) console.error(err) }

PouchDB.plugin(require('pouchdb-adapter-memory'))

// TODO: migrated to native-crypto
// https://www.npmjs.com/package/native-crypto

function cypherStream (sec, stream) {
  var encoder = crypto.createCypher('aes192', sec)
  encoder.pipe(stream)
  return duplexify(encoder, stream.pipe(crypto.createDecipher('aes192', sec)))
}

// TODO: the most efficient thing to do this will be
// to ask each node over RPC what nodes it is connected to and create
// offers in the database, then push replicate its locally populated
// signals db.
// *Then* it should write its peer record.
// The code that picks up new peers in the changes feed should also
// not create new initiators for.

function setupPeer (swarm, peer) {
  function emit () {
    swarm.emit.apply(swarm, arguments)
    peer.emit.apply(peer, arguments)
  }

  let plex = multiplex((stream, id) => {
    let type
    let toPublicKey
    let direction
    if (id.slice(0, 'relay:'.length) === 'relay:') {
      [type, direction, toPublicKey] = type.split(':')
    } else {
      type = id
    }

    switch (type) {
      case 'db':
        emit('db', peer.publicKey)
        let encoder = jsonstream.stringify()
        let opts = {live: true, since: 0, include_docs: true}
        swarm.db.changes(opts).on('change', change => {
          encoder.write(change)
        })
        encoder.pipe(stream)

        // TODO: setup signature validation
        break
      case 'dnode':
        let d = dnode(swarm.rpc)
        d.pipe(stream).pipe(d)
        break
      case 'relay':
        let relayid
        if (direction === 'to') {
          // receive and decode stream
          // TODO: implement
        } else {
          // Send stream to publicKey
          relayid = `relay:from:${peer.publicKey}`
          let s = swarm.peer[toPublicKey].plex.createStream(relayid)
          stream.pipe(s).pipe(stream)
        }
        break
      default:
        emit('stream', stream, id)
    }
  })

  // function relay () {
  //   // TODO
  //   var secret = swarm.computeSecret(toPublicKey)
  //   stream = cypherStream(secret, stream)
  //   stream.publicKey = peer.publicKey
  // }

  plex.pipe(peer).pipe(plex)

  // Setup dnode
  let dnodeStream = plex.createStream('dnode')
  let d = dnode()
  d.on('remote', remote => {
    remote.publicKey = peer.publicKey
    swarm.remotes[peer.publicKey] = remote
    emit('remote', remote)
  })
  d.publicKey = peer.publicKey
  dnodeStream.pipe(d).pipe(dnodeStream)

  // Setup DB replication
  let decoder = jsonstream.parse('*')
  let dbStream = plex.createStream('db')

  dbStream.pipe(decoder).pipe(through2.obj((change, enc, cb) => {
    if (!change.doc._id) throw new Error('no id')
    // TODO: implement at LRU that doesn't write documents
    // that come out of this CouchDB.
    swarm.db.put(change.doc, {new_edits: false}, (err, info) => {
      if (err) console.error('Doc did not replicate. ' + info.id)
      cb(null)
    })
  }))

  peer.plex = plex
}

// Default RPC methods
function RPC (swarm) {
  // This can't be a class-like object because dnode
  // requires that it be a regular hash object.
  let rpc = {}
  rpc.ping = cb => cb(null)
  return rpc
}

function Swarm (signalServer, opts) {
  // Crypto Setup
  let mykey = crypto.createECDH('secp521r1')
  mykey.generateKeys()
  this.publicKey = mykey.getPublicKey().toString('hex')
  let privateKey = mykey.getPrivateKey().toString('hex')

  this.db = new PouchDB(`rswarm:${this.publicKey}`, {adapter: 'memory'})
  this.rpc = RPC()

  this.maxDelay = 1000

  this.opts = opts | {}
  this.dnodes = {}
  this.remotes = {}
  this.peers = {}
  this.waiting = {}
  this.network = {}
  this.relays = {}

  this.on('remote', remote => {
    this.ping(remote.publicKey, (err, delay) => {
      if (err) return console.error('cannot ping', err)
      if (delay > this.maxDelay) {
        this.reroute(remote.publicKey)
      }
    })
  })

  let onSignal = signal => {
    if (this.waiting[signal.from]) {
      this.waiting[signal.from].signal(signal.offer)
      // TODO remove waiting once connected
    } else {
      var peer = new SimplePeer(extend(opts, {trickle: false}))
      peer.publicKey = signal.from
      peer.once('signal', offer => {
        this.sendSignal(signal.from, offer)
      })
      peer.signal(signal.offer)
      peer.on('connect', () => {
        this.peers[signal.from] = peer
        delete this.waiting[signal.from]
        setupPeer(this, peer)
        this.emit('peer', peer)
      })
    }
  }

  let _opts = {since: 'now', live: true, include_docs: true}
  this.db.changes(_opts).on('change', change => {
    let [type, fromPublicKey, toPublicKey] = change.id.split(':')
    if (type === 'peer') {
      if (fromPublicKey === this.publicKey) return // This is me.
      if (this.peers[fromPublicKey]) return
      if (this.waiting[fromPublicKey]) return
      // We have not connected to this peer.
      // Now we will write an offer to this peer
      // and repliate it into the network.
      let initiatePeerConnection = () => {
        let _opts = extend(this.opts, {initiator: true, trickle: false})
        let peer = new SimplePeer(_opts)
        peer.once('signal', offer => {
          let id = `offer:${this.publicKey}:${fromPublicKey}`
          let value = this.sendSignal.encodeOffer(fromPublicKey, offer)
          let doc = {_id: id, initiator: value, created: peer._created}
          this.db.put(doc, (err, info) => {
            if (err) return console.error('could not write', id)
            // TODO: figure out when this might happen.
          })
        })
        peer._created = Date.now()
        peer.once('connect', createOnConnect(this, peer, fromPublicKey))
      }
      if (fromPublicKey < this.publicKey) {
        initiatePeerConnection()
      } else {
        // Wait one minute to see if they have initiated a connection
        // first.
        setTimeout(() => {
          if (!this.peers[fromPublicKey]) initiatePeerConnection()
        }, 60 * 1000)
      }
    }
    if (type === 'offer') {
      if (this.peers[toPublicKey]) return
      if (this.peers[fromPublicKey]) return

      let doc = change.doc
      if (fromPublicKey === this.publicKey) {
        // Look for response in document we wrote
        if (!doc.answer) return // This is my write.

        let answer = this.sendSignal.decrypt(toPublicKey, doc.answer.offer)
        if (!this.waiting[toPublicKey]) {
          return console.error('No peer waiting.')
        }
        window.waiter = this.waiting[toPublicKey]

        this.waiting[toPublicKey].signal(answer)
      } else if (toPublicKey === this.publicKey) {
        if (doc.answer) return // This is my write.
        let offer = this.sendSignal.decrypt(fromPublicKey, doc.initiator.offer)

        if (this.waiting[fromPublicKey]) {
          if (!this.waiting[fromPublicKey]._offer) {
            if (doc.created < this.waiting[fromPublicKey]._created) {
              return // Go with most recently created offer.
            }
          }
        }
        let _opts = extend(this.opts, {trickle: false})
        let peer = new SimplePeer(_opts)
        peer.once('signal', offer => {
          doc.answer = this.sendSignal.encodeOffer(fromPublicKey, offer)
          this.db.put(doc, (err, info) => {
            if (err) return console.error('could not write', doc._id)
            // TODO: figure out when this might happen.
          })
        })

        peer.signal(offer)
        peer.once('connect', createOnConnect(this, peer, fromPublicKey))
      }
      // This offer isn't for me.
    }
  })
  let sendSignal
  if (signalServer) {
    sendSignal = signalExchange(
      signalServer,
      privateKey,
      this.publicKey,
      onSignal
    )
  } else {
    sendSignal = signalExchange(
      privateKey,
      this.publicKey,
      onSignal
    )
  }

  this.sendSignal = sendSignal
  this._callQueue = []
  sendSignal.onReady = () => {
    this._ready = true
    this._callQueue.forEach(args => this.call(...args))
    this._callQueue = []
    this.emit('ready')
    var obj = { nonce: crypto.randomBytes(10).toString('hex'),
                joined: Date.now()
              }
    this.put(`peer:${this.publicKey}`, obj, (err, info) => {
      if (err) this.emit('error', err)
    })
  }
}
util.inherits(Swarm, EventEmitter)
Swarm.prototype.put = function (key, value, cb) {
  var _value
  if (typeof value !== 'string') _value = JSON.stringify(value)
  else _value = value
  var obj = {_id: key}
  this.db.get(key, (err, orig) => {
    if (!err) obj._rev = orig._rev
    obj.value = value
    obj.signature = this.sendSignal.sign(_value).toString('hex')
    this.db.put(obj, cb)
  })
  return obj
}
Swarm.prototype.sign = function (value) {
  return this.sendSignal.sign(this.pemPrivateKey, value)
}
Swarm.prototype.call = function (pubKey, cb) {
  if (!cb) cb = noopCallback
  if (!this._ready) return this._callQueue.push([pubKey, cb])

  var _opts = extend(this.opts, {initiator: true, trickle: false})
  var peer = new SimplePeer(_opts)
  peer.publicKey = pubKey
  peer.once('signal', offer => {
    this.sendSignal(pubKey, offer)
  })
  peer.on('connect', createOnConnect(this, peer, pubKey, cb))
  this.waiting[pubKey] = peer
}
Swarm.prototype.ping = function (publicKey, cb) {
  let start = Date.now()
  this.getRemote(publicKey).ping(() => {
    let delay = Date.now() - start
    this.network[publicKey] = delay
    this.updateNetwork()
    if (cb) cb(null, delay)
  })
}
Swarm.prototype.getRemote = function (publicKey) {
  return this.remotes[publicKey]
}
Swarm.prototype.updateNetwork = function () {
  let _value = {network: this.network, relays: this.relays}
  this.put(`network:${this.publicKey}`, _value, noopCallback)
}
Swarm.prototype.reroute = function (publicKey) {
  let fastestTTL = Infinity
  let fastestPublicKey = null
  let _filter = doc => {
    if (doc._id.slice(0, 'network'.length) === 'network') {
      let pubKey = doc._id.slice('network:'.length)
      if (pubKey === this.publicKey) return
      if (!this.network[pubKey]) return
      if (!doc.value.network[publicKey]) return
      let ttl = (doc.value.network[publicKey] + this.network[pubKey] + 200)
      if (ttl < fastestTTL) {
        fastestTTL = ttl
        fastestPublicKey = pubKey
      }
    }
    return false
  }
  this.db.changes({include_docs: true, filter: _filter})
  .then(() => {
    if (fastestPublicKey && fastestTTL < this.maxDelay) {
      console.log('TODO: Relay!')
    }
  })
}

if (process.browser) {
  window.Swarm = Swarm
}

function createOnConnect (swarm, peer, pubKey, cb) {
  function _ret () {
    if (swarm.peers[pubKey]) {
      // TODO: gracefull disconnect
      return console.log('already connected')
    }
    if (cb) cb(null, peer)
    peer.publicKey = pubKey
    swarm.peers[pubKey] = peer
    delete swarm.waiting[pubKey]
    setupPeer(swarm, peer)
    swarm.emit('peer', peer)
  }
  swarm.waiting[pubKey] = peer
  return _ret
}
