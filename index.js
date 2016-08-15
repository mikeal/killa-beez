const PouchDB = require('pouchdb')
const replicationStream = require('pouchdb-replication-stream')
const multiplex = require('multiplex')
const rand = () => require('crypto').randomBytes(8).toString('hex')
const dnode = require('dnode')
const duplexify = require('duplexify')
const crypto = require('crypto')
const EventEmitter = require('events').EventEmitter
const util = require('util')
const ec_pem = require('./ec-pem')
const request = require('request')
const SimplePeer = require('simple-peer')
const _ = require('lodash')
const noop = () => {}
const noopCallback = (err) => { if (err) console.error(err) }

PouchDB.plugin(replicationStream.plugin)
PouchDB.plugin(require('pouchdb-adapter-memory'))
PouchDB.adapter('writableStream', replicationStream.adapters.writableStream)

function cypherStream (sec, stream) {
  var encoder = crypto.createCypher('aes192', sec)
  encoder.pipe(stream)
  return duplexify(encoder, stream.pipe(crypto.createDecipher('aes192', sec)))
}

function SignalServer (baseurl) {
  this.base = baseurl
}
SignalServer.prototype.get = function (pub, cb) {
  var url = `${this.base}/v1/${pub}`
  request.get(url, {json: true}, (err, resp, obj) => {
    if (err) return cb(err)
    var status = resp.statusCode
    if (status !== 200) return cb(new Error('Status Code not 200, ' + status))
    cb(null, obj)
  })
}
SignalServer.prototype.put = function (pub, obj, cb) {
  var url = `${this.base}/v1/${pub}`
  request.put(url, {json: obj}, (err, resp, obj) => {
    if (err) return cb(err)
    var status = resp.statusCode
    if (status !== 201) return cb(new Error('Status Code not 201, ' + status))
    cb(null, obj)
  })
}

function setupPeer (swarm, peer) {
  var plex = multiplex((stream, id) => {
    var [type, publicKey] = id.slice(':')

    // TODO relay

    function emit () {
      swarm.emit.apply(swarm, arguments)
      peer.emit.apply(peer, arguments)
    }

    var secret = swarm.mykey.computeSecret(publicKey)
    stream = cypherStream(secret, stream)
    stream.publicKey = publicKey
    switch (type) {
      case 'db':
        swarm.db.dump(stream)
        swarm.db.load(stream)
        emit('db', publicKey)
        // TODO: setup signature validation
        break
      case 'dnode':
        var d = dnode(swarm.rpc)
        d.publicKey = publicKey
        d.on('remote', remote => {
          remote.publicKey = publicKey
          swarm.remotes[publicKey] = remote
          emit('remote', remote)
        })

        emit('dnode', dnode)
        d.pipe(stream).pipe(d)
        swarm.dnodes[publicKey] = d
        break

      default:
        emit('stream', stream, id)
    }
  })
  plex.pipe(peer).pipe(plex)
  plex.createStream(`dnode:${this.publicKey}`)
  plex.createStream(`db:${this.publicKey}`)
  peer.plex = plex
}

function Swarm (signaler, opts) {
  // Crypto Setup
  this.mykey = crypto.createECDH('secp521r1')
  this.mykey.generateKeys()
  this.publicKey = this.mykey.getPublicKey().toString('hex')
  this.pem = ec_pem(this.mykey, 'secp521r1')
  this.pemPrivateKey = this.pem.encodePrivateKey()

  this.db = new PouchDB(rand(), {adapter: 'memory'})
  this.opts = opts | {}
  this.signaler = signaler
  this.rpc = {}
  this.dnodes = {}
  this.remotes = {}
  this.peers = {}
  this.setInitiator(noopCallback)
}
util.inherits(Swarm, EventEmitter)
Swarm.prototype.setInitiator = function (cb) {
  // Create a simple peer and store the offer
  // TODO: make it kick itself so that an active
  // initiator is always available.
  var initOpts = {initiator: true, trickle: false}

  this.initiator = new SimplePeer(_.extend(this.opts, initOpts))
  this.initiator.once('signal', offer => {
    var obj = this.put('signal', offer, cb)
    this.signaler.put(this.publicKey, obj, (err) => {
      if (err) return this.emit('error', err)
      this.emit('signal', offer)
    })
    // TODO: cleanup after a timeout and reset
  })
  this.initiator.once('connect', () => {
    setupPeer(this, this.initiator)
    this.emit('peer', this.initiator)
    this.setInitiator(noopCallback)
  })
}
Swarm.prototype.put = function (key, value, cb) {
  key = this.publicKey + ':' + key
  var _value
  if (typeof value !== 'string') _value = JSON.stringify(value)
  else _value = value
  var obj = {_id: key}
  obj.value = value
  obj.signature = this.sign(_value).toString('hex')
  this.db.get(key, (err, orig) => {
    if (!err) obj._rev = orig._rev
    this.db.put(obj, cb)
  })
  return obj
}
Swarm.prototype.sign = function (value) {
  if (typeof value !== 'string') value = JSON.stringify(value)
  var algo = 'ecdsa-with-SHA1'
  return crypto.createSign(algo).update(value).sign(this.pemPrivateKey)
}
Swarm.prototype.verify = function (value, publicKey, signature) {
  if (!Buffer.isBuffer(publicKey)) publicKey = new Buffer(publicKey, 'hex')
  if (typeof value !== 'string') value = JSON.stringify(value)
  var c = 'secp521r1'
  var pem = ec_pem({public_key: publicKey, curve: c}, c).encodePublicKey()
  var algo = 'ecdsa-with-SHA1'
  return crypto.createVerify(algo).update(value).verify(pem, signature)
}

Swarm.prototype.getSignal = function (key, cb) {
  // Gets an offer from the server for the given publicKey
  this.signaler.get(key, (err, obj) => {
    if (err) return cb(err)
    if (!this.verify(obj.value, key, new Buffer(obj.signature, 'hex'))) {
      return cb(new Error('Offer signature failed validation.'))
    }
    console.log('offer ok', obj.value)
    cb(null, obj.value)
  })
}
Swarm.prototype.signal = function (offer, cb) {
  if (!cb) cb = noopCallback
  if (typeof offer === 'string') {
    this.getSignal(offer, (err, offer) => {
      if (err) return cb(err)
      this.signal(offer, cb) // TODO: add retries if offer expires
    })
    return
  }
  console.log('creating peer', offer)
  var peer = new SimplePeer(_.extend(this.opts, {trickle: false}))
  peer.on('connect', () => {
    console.log('connected')
    setupPeer(this, peer)
    this.emit('peer', peer)
  })
  peer.signal(offer)
  peer.on('signal', (signal) => {
    // TODO: Figure out the other side of the signalling.
    console.log('signal')
  })
}


if (process.browser) {
  window.Swarm = Swarm
  window.SignalServer = SignalServer
}