import assert from 'node:assert/strict'
import {createSSRApp, h} from 'vue'
import {renderToString} from 'vue/server-renderer'
import {createServer} from 'vite'

const vite = await createServer({optimizeDeps: {noDiscovery: true, include: []}, server: {middlewareMode: true, hmr: false, watch: null}, appType: 'custom'})
try {
  const {default: Trace} = await vite.ssrLoadModule('/src/TransferTrace.vue')
  const session = 'd7cb614d-d318-49a6-af06-b2bde80603bc'
  const trace = {session_id: session, download: [[0,0],[100,12500],[250,50000]], upload: []}
  const render = props => renderToString(createSSRApp({render: () => h(Trace, props)}))
  const output = await render({session: session.toUpperCase(), trace})
  assert.match(output, /Maksimum próbek 2 Mb\/s/)
  assert.match(output, /Brak próbek dla tego kierunku/)
  assert.match(output, /<polyline /)
  for (const props of [{session}, {session: 'inna-sesja', trace}]) {
    const empty = await render(props)
    assert.match(empty, /Ten zapis nie zawiera próbek/)
    assert.doesNotMatch(empty, /<polyline /)
  }
  console.log('Transfer chart, missing direction and historical reports passed')
} finally {
  await vite.close()
}
