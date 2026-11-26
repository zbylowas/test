import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'

const root = new URL('../dist/', import.meta.url)
const html = readFileSync(new URL('index.html', root), 'utf8')
const match = html.match(/src="\/assets\/([^"]+\.js)"/)
assert.ok(match, 'Missing application bundle')
const bundle = new TextDecoder('utf-8', {fatal: true}).decode(readFileSync(new URL('assets/' + match[1], root)))
for (const label of ['Sprawdź swoje', 'Pobierz instalator Windows', 'Wersja przenośna EXE', 'Wysyłanie', 'Opóźnienie HTTPS', 'wklej']) {
  assert.ok(bundle.includes(label), 'Invalid Polish copy in release bundle: ' + label)
}
