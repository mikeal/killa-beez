const http = require('http')
const response = require('response')
const LRU = require('lru')
const body = require('body/json')
const corsify = require('corsify')

const cache = new LRU(1000)
const links = {}
const cors = corsify({
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE',
  'Access-Control-Allow-Headers': 'X-Requested-With, X-HTTP-Method-Override, Content-Type, Accept, Authorization'
})
const server = http.createServer(cors(listener))

function listener (req, res) {
  if (req.url === '/') {
    return // TODO: status message
  }
  console.log('request', req.url)
  var [version, key, name] = req.url.split('/').filter(x => x)
  console.log(version, key, name)

  if (version !== 'v1') return response.error(404).pipe(res)
  if (key === 'name') {
    if (!name) return response.error(404).pipe(res)
    if (req.method === 'PUT') {
      body(req, (err, obj) => {
        if (err) return response.error(err).pipe(res)
        links[name] = obj._id
        cache.set(obj._id, obj)
        return response().status(201).pipe(res)
      })
      return
    }
    if (req.method === 'GET') {
      if (!links[name]) return response.error(404).pipe(res)
      if (!cache.get(links[name])) return response.error(404).pipe(res)
      return response.json(cache.get(links[name])).pipe(res)
    }
  }
  if (!key || name) return response.error(404).pipe(res)
  console.log('in cache access')
  console.log(req)
  if (req.method === 'GET') {
    if (!cache.get(key)) return response.error(404).pipe(res)
    return response.json(cache.get(key)).pipe(res)
  }
  if (req.method === 'PUT') {
    body(req, (err, obj) => {
      console.log(key, obj)
      if (err) return response.error(err).pipe(res)
      cache.set(key, obj)
      return response.json(obj).status(201).pipe(res)
    })
    return
  }

  return response.error(404).pipe(res)
}

server.listen(6688, () => {
  console.log('listening on 6688')
})
