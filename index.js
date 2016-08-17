const PouchDB = require('pouchdb')
const replicationStream = require('pouchdb-replication-stream')
const multiplex = require('multiplex')
const crypto = require('crypto')
const rand = () => crypto.randomBytes(8).toString('hex')
const dnode = require('dnode')
const duplexify = require('duplexify')
const EventEmitter = require('events').EventEmitter
const util = require('util')
const ec_pem = require('./ec-pem')
const SimplePeer = require('simple-peer')
const extend = require('lodash.assign')
const io = require('socket.io-client')

const noopCallback = (err) => { if (err) console.error(err) }

PouchDB.plugin(replicationStream.plugin)
PouchDB.plugin(require('pouchdb-adapter-memory'))
PouchDB.adapter('writableStream', replicationStream.adapters.writableStream)

function cypherStream (sec, stream) {
  var encoder = crypto.createCypher('aes192', sec)
  encoder.pipe(stream)
  return duplexify(encoder, stream.pipe(crypto.createDecipher('aes192', sec)))
}

function sign (pemPrivateKey, value) {
  if (typeof value !== 'string') value = JSON.stringify(value)
  var algo = 'ecdsa-with-SHA1'
  return crypto.createSign(algo).update(value).sign(pemPrivateKey).toString('hex')
}
function verify (value, publicKey, signature) {
  if (!Buffer.isBuffer(publicKey)) publicKey = new Buffer(publicKey, 'hex')
  if (typeof value !== 'string') value = JSON.stringify(value)
  var c = 'secp521r1'
  var pem = ec_pem({public_key: publicKey, curve: c}, c).encodePublicKey()
  var algo = 'ecdsa-with-SHA1'
  return crypto.createVerify(algo).update(value).verify(pem, signature)
}
function computeSecret (fromPrivateKey, toPublicKey) {
  let priv = crypto.createECDH('secp521r1')
  priv.generateKeys()
  priv.setPrivateKey(fromPrivateKey, 'hex')
  let secret = priv.computeSecret(toPublicKey, 'hex', 'hex')
  return secret
}
function encrypt (fromPrivateKey, toPublicKey, data) {
  if (typeof data !== 'string') data = JSON.stringify(data)
  // TODO: finish encryption
  let secret = computeSecret(fromPrivateKey, toPublicKey)

  let cipher = crypto.createCipher('aes192', secret);

  var encrypted = cipher.update(data, 'utf8', 'hex')
  encrypted += cipher.final('hex')
  return encrypted
}
function decrypt (toPrivateKey, fromPublicKey, data) {
  let secret = computeSecret(toPrivateKey, fromPublicKey)
  let decipher = crypto.createDecipher('aes192', secret)
  var decrypted = decipher.update(data, 'hex', 'utf8')
  decrypted += decipher.final('utf8')
  var ret = JSON.parse(decrypted)
  return ret
}

function signalExchange (host, privateKey, publicKey, onOffer) {
  var socket = io(host)
  var c = 'secp521r1'
  var pem = ec_pem({private_key: privateKey, curve: c}, c)
  var pemPrivateKey = pem.encodePrivateKey()

  var data = {verify: true, nonce: crypto.randomBytes().toString('hex')}
  socket.emit('subscribe', publicKey, data, sign(pemPrivateKey, data))

  socket.on('signal', data => {
    // TODO: wrap in try/catch
    data.offer = decrypt(privateKey, data.from, data.offer)
    delete data.signature // This is the unencrypted signature
    onOffer(data)
  })
  socket.on('offer-error', (msg) => {
    console.error('offer-error:', msg)
  })
  function encodeOffer (pubKey, offer) {
    let data = {from: publicKey, to: pubKey}
    data.offer = encrypt(privateKey, pubKey, offer)
    data.signature = sign(pemPrivateKey, data.offer)
    return data
  }
  function send (pubKey, offer) {
    let data = encodeOffer(pubKey, offer)
    socket.emit('signal', data)
  }
  // send.encodeOffer = encodeOffer
  return send
}

function setupPeer (swarm, peer) {
  var plex = multiplex((stream, id) => {
    var [type, publicKey] = id.slice(':')

    // TODO relay

    function emit () {
      swarm.emit.apply(swarm, arguments)
      peer.emit.apply(peer, arguments)
    }

    var secret = swarm.mykey.computeSecret(peer.publicKey)
    stream = cypherStream(secret, stream)
    stream.publicKey = peer.publicKey
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

function Swarm (signalServer, opts) {
  // Crypto Setup
  this.mykey = crypto.createECDH('secp521r1')
  this.mykey.generateKeys()
  this.publicKey = this.mykey.getPublicKey().toString('hex')
  this.privateKey = this.mykey.getPrivateKey().toString('hex')
  this.pem = ec_pem(this.mykey, 'secp521r1')
  this.pemPrivateKey = this.pem.encodePrivateKey()

  this.db = new PouchDB(rand(), {adapter: 'memory'})
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
      peer.once('signal', offer => {
        this.sendSignal(signal.from, offer)
      })
      peer.signal(signal.offer)
      peer.on('connect', () => {
        this.peers[signal.from] = peer
        delete this.waiting[signal.from]
        this.emit('peer', peer)
      })
      console.log('created new peer')
    }
  }
  this.db.changes({
    since: 'now'
  }).on('change', function (change) {
    console.log('change', change)
    // received a change
  }).on('error', function (err) {
    // handle errors
    console.error('db', err)
  })


  var sendSignal = signalExchange(
    signalServer,
    this.privateKey,
    this.publicKey,
    onSignal
  )
  this.sendSignal = sendSignal
}
util.inherits(Swarm, EventEmitter)
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
  return sign(this.pemPrivateKey, value)
}
Swarm.prototype.verify = verify

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
Swarm.prototype.call = function (pubKey, cb) {
  if (!cb) cb = noopCallback
  var _opts = extend(this.opts, {initiator: true, trickle: false})
  var peer = new SimplePeer(_opts)
  peer.once('signal', offer => {
    this.sendSignal(pubKey, offer)
  })
  peer.on('connect', () => {
    // probably do setup here.
    cb(null, peer)
    this.peers[pubKey] = peer
    delete this.waiting[pubKey]
    this.emit('peer', peer)
  })
  this.waiting[pubKey] = peer
}


if (process.browser) {
  window.Swarm = Swarm
}