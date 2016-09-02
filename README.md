# Killa Beez

***We on a swarm!***

```
npm install killa-beez
```

***Experimental***: This module is still under heavy and active
development. While each release should work features and functionality
may be deprecated and not all the goals of the project have been
acheived yet.

`Killa Beez` is an efficient, secure, and reliable WebRTC swarm. The
goal is to not rely on any single point of failure and to resist
hostile networks.

The goal is also to be performant when some peers have poor network
conditions by using the closest peer as a relay similar to how Skype's
"Super Nodes."

Any peer can connect to the swarm given the public key of *any* node in the
network.

```javascript
let node1 = new Swarm()
let node2 = new Swarm()
let node3 = new Swarm()

// This will print 6 times, as each peer connects to both other peers.
node1.on('peer', peer => console.log('peer1 got', peer.publicKey))
node2.on('peer', peer => console.log('peer2 got', peer.publicKey))
node3.on('peer', peer => console.log('peer3 got', peer.publicKey))

node1.call(node2.publicKey) // connect peers 1 and 2 together
node3.call(node1.publicKey) // connect peers 3 and 1 together
// This will end up connecting all three
// nodes together even though only two
// call each other through signal exchange.
```

## Departures for v1

* Rename from "Resilient Swarm" to "Killa Beez."
* Remove pouchbd, move to pure RPC (via dnode) for relaying peers.
* Support the a signing key along with a signature chain during instantiation.

### Principals

* Each `Swarm` instance generates an ECDH public/private keypair for its node.
  * Each node uses signal-exchange to register it's public key and await
    signals.
  * Another swarm node looks up the public key through the signaling mechanism
    to exchange initial offers.
  * Once a connection is established (using `SimplePeer`) the data channel is
    multiplexed. The substeams are keyed with a `type`.
* There are currently two types of substeams in the data channel that are
  ciphered.
  * `dnode` is an rpc steam for communication between peers using [dnode]().
  * `relay` Used to proxy data from one peer to another when the intermediate
    peer has better connectivity. The `publicKey` used to setup a
    Cipher stream so that the relaying node cannot read the traffic.
