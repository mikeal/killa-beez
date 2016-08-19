# ResilientSwarm

```
npm install resilient-swarm
```

`ResilientSwarm` is an efficient, secure, and reliable WebRTC swarm. The
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
node1.once('signal', () => {
  node2.signal(node1.publicKey)
})
node1.once('ready', () => {
  node2.call(node1.publicKey)
})

node1.on('peer', peer => console.log('peer1 got', peer.publicKey))
node2.on('peer', peer => console.log('peer2 got', peer.publicKey))

node1.once('peer', peer => {
  let node3 = new Swarm()
  node3.call(node1.publicKey)
  node3.on('peer', peer => {
    console.log(( (Date.now() - starttime) / 1000 ) + 's')
    console.log('peer3 got', peer.publicKey)
  })
})
```

### Principals

* Each `Swarm` instance generates an ECDH public/private keypair for its node.
  * Each node uses signal-exchange to register it's public key and await
    signals.
  * Another swarm node looks up the public key through the signaling mechanism
    to exchange initial offers.
    * Currently this is done via a central server but ideally this would be
      something more resilient like IPFS.
  * Once a connection is established (using `SimplePeer`) the data channel is
    multiplexed. The substeams are keyed with a `type`.
* There are currently three types of substeams in the data channel that are
  ciphered.
  * `db` is a pouchdb database replication stream. Once established
    bi-directional replication is setup between each node's internal pouchdb
    instance.
  * `dnode` is an rpc steam for communication between peers using [dnode]().
  * `relay` Used to proxy data from one peer to another when the intermediate
    peer has better connectivity. The `publicKey` used to setup a
    Cipher stream so that the relaying node cannot read the traffic.
* In addition to storing peer information the local database is replicated
  with every node in the network. This means that in order to join the swarm
  **a user only needs to connect to one node in the swarm** and will then be
  able to get signals to every other peer and share its active signal with every
  node in the swarm.

