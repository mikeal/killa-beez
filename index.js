const PouchDB = require('pouchdb')
const multiplex = require('multiplex')
const crypto = require('crypto')
const rand = () => crypto.randomBytes(8).toString('hex')
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

function setupPeer (swarm, peer) {
  let plex = multiplex((stream, id) => {
    let type
    let toPublicKey
    let direction
    if (id.slice(0, 'relay:'.length) === 'relay:') {
      [type, direction, toPublicKey] = type.split(':')
    } else {
      type = id
    }

    // TODO relay

    function emit () {
      swarm.emit.apply(swarm, arguments)
      peer.emit.apply(peer, arguments)
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
        var d = dnode(swarm.rpc)
        d.publicKey = peer.publicKey
        d.on('remote', remote => {
          remote.publicKey = peer.publicKey
          swarm.remotes[peer.publicKey] = remote
          emit('remote', remote)
        })

        emit('dnode', dnode)
        d.pipe(stream).pipe(d)
        swarm.dnodes[peer.publicKey] = d
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
  plex.createStream('dnode')
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

function Swarm (signalServer, opts) {
  // Crypto Setup
  let mykey = crypto.createECDH('secp521r1')
  mykey.generateKeys()
  let publicKey = mykey.getPublicKey().toString('hex')
  let privateKey = mykey.getPrivateKey().toString('hex')

  this.db = new PouchDB(rand(), {adapter: 'memory'})
  this.publicKey = publicKey
  this.opts = opts | {}
  this.rpc = {}
  this.dnodes = {}
  this.remotes = {}
  this.peers = {}
  this.waiting = {}
  // this.setInitiator(noopCallback)
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

  var sendSignal = signalExchange(
    signalServer,
    privateKey,
    publicKey,
    onSignal
  )
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
  obj.value = value
  obj.signature = this.sendSignal.sign(_value).toString('hex')
  this.db.get(key, (err, orig) => {
    if (!err) obj._rev = orig._rev
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
  peer.on('connect', () => {
    // probably do setup here.
    cb(null, peer)
    this.peers[pubKey] = peer
    delete this.waiting[pubKey]
    setupPeer(this, peer)
    this.emit('peer', peer)
  })
  this.waiting[pubKey] = peer
}

if (process.browser) {
  window.Swarm = Swarm
}
