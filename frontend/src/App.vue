<script setup lang="ts">
/// <reference types="vite/client" />
import {ref, computed, onMounted} from 'vue'
import InventoryReport, {type Inventory, type Reading} from './InventoryReport.vue'
const showSources=import.meta.env.VITE_SOURCE_VISIBILITY!=='private'

type Session = {session_id:string; started_at:string; state:string; client_version:string;ip:string;sync_ip:string;ip_source:'reservation'|'sync';client_id:string;device_id:string|null;device_method:string|null;device_reason:string|null}
type Direction = {goodput_mbps:number|null; bufferbloat:string; median_increase_ms:number|null}
type Phase = {median_ms:number|null;p95_ms:number|null;sent:number;received:number}
type Transfer = {interpretation:{directions:Record<string,Direction>; phases:Record<string,Phase>}; throughput:{reservation_local_ip?:Reading<string>;error:string|null;windows_version:string;node_id:string|null;profile:{rate_bps:number;streams?:number;window_ms?:number}|null}}
type Hop = {snt:number;rcv:number;responders:string[];loss_pct:number|null;p50:number|null;p95:number|null}
type Analysis = {result:{sample_count:number; series:{target:string;protocol:string;phase:string;stats:Record<string,Hop>}[];findings:{limitations:string;recommended_tests:string[]}[]}}
const admin=location.pathname==='/admin', landing=location.pathname==='/'
const publisher=ref('Sprawdzanie podpisu wydania…')
onMounted(async()=>{
 if(!landing)return
 try {
  const response=await fetch('/pobierz/windows-release.json',{cache:'no-store'})
  if(!response.ok)throw new Error()
  const release=await response.json()
  if(release.authenticode.status==='Valid')publisher.value='Podpis Authenticode · '+release.authenticode.publisher
  else if(release.authenticode.status==='NotSigned')publisher.value='Plik bez podpisu wydawcy (Authenticode).'
  else throw new Error()
 }catch{publisher.value='Brak informacji o podpisie wydania.'}
})
const access=ref(''), logged=ref(false), error=ref(''), busy=ref(false)
const sessions=ref<Session[]>([]), filter=ref(''), offset=ref(0), more=ref(false)
const selected=ref<Session|null>(null), transfer=ref<Transfer|null>(null), analysis=ref<Analysis|null>(null)
const inventory=ref<Inventory|null>(null), loadingReport=ref(false), reportError=ref('')
const searchIp=ref(''), searchDevice=ref(''), searchOwner=ref('')
type Sample = {phase:string;ttl:number;attempt:number;responder:string|null;rtt_ms:number|null;status:string}
const raw=ref<Sample[]>([]), rawOffset=ref(0), rawMore=ref(false), rawBusy=ref(false), rawError=ref('')
let token='', serial=0
const names:Record<string,string>={completed:'Zakończony',partial:'Częściowy',open:'W toku',cancelled:'Przerwany',failed:'Błąd',baseline:'W spoczynku',download:'Pobieranie',upload:'Wysyłanie',recovery:'Po obciążeniu'}
const diagnosis:Record<string,string>={possible_bufferbloat:'Możliwy bufferbloat',not_observed_at_measured_rate:'Bez istotnego wzrostu opóźnienia',inconclusive:'Za mało danych do rozstrzygnięcia'}
const directions=['download','upload']
const phaseOrder=['baseline','download','upload','recovery']
const title=computed(()=>admin?'Panel administratora':'Panel klienta')
function number(n:number|null|undefined){return n==null?'—':n.toLocaleString('pl-PL',{maximumFractionDigits:2})}
function date(s:string){return new Date(s).toLocaleString('pl-PL')}
async function api(path:string, optional=false) {
 const response=await fetch('/api/v1/'+path,{headers:{Authorization:'Bearer '+token},cache:'no-store',redirect:'error'})
 if(optional && response.status===404) return null
 if(!response.ok) throw new Error(response.status===401?'Nieprawidłowy lub wygasły kod dostępu.':response.status===429?'Osiągnięto limit zapytań. Spróbuj za chwilę.':'Serwer nie udostępnił danych (HTTP '+response.status+').')
 return response.json()
}
async function login(){
 busy.value=true;error.value='';token=access.value.trim()
 try {
  const me=await api('portal/me')
  if(me.role!==(admin?'operator':'client')) throw new Error('Ten kod jest przypisany do innego panelu.')
  logged.value=true;access.value='';await list(0)
 }catch(e){logout();error.value=(e as Error).message}finally{busy.value=false}
}
function logout(){searchIp.value='';searchDevice.value='';searchOwner.value='';raw.value=[];++serial;busy.value=false;token='';access.value='';logged.value=false;sessions.value=[];selected.value=null;transfer.value=null;analysis.value=null;inventory.value=null;reportError.value='';error.value='';loadingReport.value=false}
async function list(start:number){
 busy.value=true;error.value='';selected.value=null;reportError.value=''
 const current=++serial
 try {
  const p=new URLSearchParams({limit:'20',offset:String(start)})
  if(filter.value)p.set('state',filter.value)
  if(searchIp.value.trim())p.set('ip',searchIp.value.trim())
  if(searchDevice.value.trim())p.set('device_id',searchDevice.value.trim())
  if(searchOwner.value)p.set('client_id',searchOwner.value)
  const data=await api('portal/sessions?'+p)
  if(current!==serial)return
  sessions.value=data.items;more.value=data.has_more;offset.value=start
 }catch(e){if(current===serial){sessions.value=[];more.value=false;error.value=(e as Error).message}}
 finally{if(current===serial)busy.value=false}
}
async function open(row:Session){
 raw.value=[];rawOffset.value=0;rawMore.value=false;rawBusy.value=false;rawError.value=''
 const current=++serial;selected.value=row;loadingReport.value=true;reportError.value=''
 transfer.value=null;analysis.value=null;inventory.value=null
 try{
  const base='sessions/'+encodeURIComponent(row.session_id)+'/'
  const [t,a,i]=await Promise.all([api(base+'throughput',true),api(base+'analysis',true),api(base+'inventory',true)])
  if(current===serial){transfer.value=t;analysis.value=a;inventory.value=i}
 }catch(e){if(current===serial)reportError.value=(e as Error).message}
 finally{if(current===serial)loadingReport.value=false}
}
function deviceHistory(row:Session){
 searchIp.value='';searchDevice.value=row.device_id||'';searchOwner.value=row.client_id;list(0)
}
function clearFilters(){filter.value='';searchDevice.value='';searchOwner.value='';searchIp.value='';list(0)}
async function loadRaw(start:number){
 const row=selected.value,current=serial
 if(!row||rawBusy.value)return
 rawError.value='';rawBusy.value=true
 try{
  const data=await api('sessions/'+encodeURIComponent(row.session_id)+'/mtr?limit=64&offset='+start)
  if(current===serial){raw.value=data.items;rawOffset.value=start;rawMore.value=data.has_more}
 }catch(e){if(current===serial)rawError.value=(e as Error).message}
 finally{if(current===serial)rawBusy.value=false}
}
function exportJson(){
 if(!selected.value)return
 const blob=new Blob([JSON.stringify({session:selected.value,throughput:transfer.value,analysis:analysis.value,inventory:inventory.value},null,2)],{type:'application/json'})
 const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download='vipnet-'+selected.value.session_id+'.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)
}
function printReport(){window.print()}
</script>

<template>
<header><div class="bar"><a class="brand" href="/"><span class="mark" aria-hidden="true">▥</span> VIP-NET</a><nav aria-label="Panele"><a href="/klient" :aria-current="!landing&&!admin?'page':undefined">Panel klienta</a><a href="/admin" :aria-current="admin?'page':undefined">Administracja</a></nav></div></header>
<main>
<template v-if="landing">
<section class="hero"><div><p class="eyebrow">Diagnostyka łącza</p><h1>Sprawdź swoje<br>połączenie.</h1><p class="lead">Zmierz pobieranie, wysyłanie i opóźnienie pod obciążeniem. Wynik zobaczysz od razu w aplikacji.</p><a class="button" href="/pobierz/VIP-NET-Diagnostyka.exe" download>↓ &nbsp; Pobierz aplikację</a><small>Windows 10 i 11 · x64 · wersja testowa 0.5.3</small><small>{{publisher}} <a href="/pobierz/VIP-NET-Diagnostyka.exe.sha256">Suma kontrolna SHA-256</a><template v-if="showSources"> · <a href="https://github.com/zbylowas/test">Kod źródłowy (MIT)</a> · <a href="https://github.com/zbylowas/test#code-signing-policy">Zasady podpisywania aplikacji</a></template></small></div>
<aside class="guide"><h2>Jak wykonać pomiar</h2><ol><li>Pobierz i otwórz <strong>VIP-NET-Diagnostyka.exe</strong>.</li><li>Kliknij <strong>Wykonaj test</strong> i poczekaj na raport.</li><li>Aby wrócić do wyników w przeglądarce, wybierz <strong>Kopiuj kod do panelu</strong> w aplikacji.</li></ol><a href="/klient">Otwórz historię pomiarów →</a></aside></section>
</template>
<template v-else-if="!logged">
<section class="login"><p class="eyebrow">VIP-NET / Diagnostyka</p><h1>{{title}}</h1><p>{{admin?'Zaloguj się kodem operatora, aby przejrzeć sesje klientów swojej organizacji.':'W aplikacji Windows wybierz „Kopiuj kod do panelu”, a następnie wklej go poniżej.'}}</p>
<form @submit.prevent="login"><label for="access">Kod dostępu</label><input id="access" v-model="access" type="password" required maxlength="256" autocomplete="off"><button :disabled="busy">Otwórz panel</button></form><p v-if="error" role="alert">{{error}}</p><a v-if="!admin" href="/pobierz/VIP-NET-Diagnostyka.exe" download>Pobierz aplikację Windows ↓</a></section>
</template>
<template v-else>
<div class="section-head"><div><p class="eyebrow">{{title}}</p><h1>{{admin?'Sesje organizacji':'Moje pomiary'}}</h1></div><button class="quiet" @click="logout">Wyloguj</button></div>
<div class="toolbar"><label>Stan pomiaru <select v-model="filter" :disabled="busy" @change="list(0)"><option value="">Wszystkie</option><option v-for="s in ['completed','partial','open','cancelled','failed']" :value="s" :key="s">{{names[s]}}</option></select></label>
<label>Adres IP <input v-model="searchIp" placeholder="IPv4 lub IPv6" @keyup.enter="list(0)"></label>
<label>Identyfikator komputera <input v-model="searchDevice" @input="searchOwner=''" @keyup.enter="list(0)"></label>
<button class="quiet" :disabled="busy" @click="list(0)">Szukaj</button><button v-if="searchIp||searchDevice||filter" class="quiet" @click="clearFilters">Wyczyść</button>
<button class="quiet" :disabled="busy" @click="list(offset)">Odśwież</button></div>
<p v-if="error" role="alert">{{error}}</p><p v-if="!sessions.length && !busy && !error" class="empty">Brak sesji dla wybranego filtra.</p>
<div v-if="sessions.length" class="scroll"><table><thead><tr><th>Rozpoczęcie</th><th>Stan</th><th>Adres IP</th><th>Identyfikator komputera</th><th>Windows EXE</th><th>Raport</th></tr></thead><tbody><tr v-for="row in sessions" :key="row.session_id"><td>{{date(row.started_at)}}</td><td>{{names[row.state]}}</td><td>{{row.ip}}<small>{{row.ip_source==='reservation'?'przy rezerwacji':'przy synchronizacji'}}</small></td><td><button v-if="row.device_id" class="link" @click="deviceHistory(row)">{{row.device_id}}</button><span v-else>{{row.device_reason||'Brak w zapisie'}}</span></td><td>{{row.client_version}}</td><td><button class="link" :disabled="busy" @click="open(row)">Otwórz</button></td></tr></tbody></table></div>
<div class="pager" v-if="offset||more"><button class="quiet" :disabled="!offset||busy" @click="list(offset-20)">Poprzednie</button><button class="quiet" :disabled="!more||busy" @click="list(offset+20)">Następne</button></div>
<article v-if="selected" class="report"><p class="eyebrow">Raport z pomiaru</p><h2>{{date(selected.started_at)}}</h2><small>Sesja {{selected.session_id}}</small>
<p>IP {{selected.ip_source==='reservation'?'przy rezerwacji':'przy synchronizacji'}} · {{selected.ip}}<span v-if="selected.ip!==selected.sync_ip"> · IP synchronizacji {{selected.sync_ip}}</span><br>Identyfikator komputera · {{selected.device_id||'Brak w zapisie'}} <span v-if="selected.device_reason">({{selected.device_reason}})</span></p>
<p v-if="loadingReport" role="status">Pobieranie raportu…</p><p v-else-if="reportError" role="alert">{{reportError}}</p>
<template v-else>
<div v-if="transfer"><p v-if="transfer.throughput.error" role="status">Pomiar częściowy · {{transfer.throughput.error}}</p><div class="metrics"><section v-for="dir in directions" :key="dir"><h3>{{names[dir]}}</h3><strong>{{number(transfer.interpretation.directions[dir]?.goodput_mbps)}} <em>Mb/s</em></strong><p>{{diagnosis[transfer.interpretation.directions[dir]?.bufferbloat]}}</p></section></div>
<p v-if="transfer.throughput.profile">Limit węzła {{number(transfer.throughput.profile.rate_bps/1000000)}} Mb/s<span v-if="transfer.throughput.profile.streams"> · strumienie {{transfer.throughput.profile.streams}} · okno {{number((transfer.throughput.profile.window_ms||0)/1000)}} s</span></p><h3>Opóźnienie HTTPS</h3><div class="scroll"><table><thead><tr><th>Faza</th><th>Mediana</th><th>P95</th><th>Odpowiedzi</th></tr></thead><tbody><tr v-for="k in phaseOrder" :key="k"><td>{{names[k]}}</td><td>{{number(transfer.interpretation.phases[k]?.median_ms)}} ms</td><td>{{number(transfer.interpretation.phases[k]?.p95_ms)}} ms</td><td>{{transfer.interpretation.phases[k]?.received}} / {{transfer.interpretation.phases[k]?.sent}}</td></tr></tbody></table></div></div>
<p v-else>Brak danych o transferze dla tej sesji.</p>
<p v-if="!analysis">Analiza MTR jest niedostępna lub oczekuje na przetworzenie. <button class="link" @click="open(selected)">Odśwież raport</button></p><template v-else><h3>Trasa MTR · {{analysis.result.sample_count}} próbek</h3><p v-for="f in analysis.result.findings" :key="f.limitations">{{f.limitations}} {{f.recommended_tests.join(' ')}}</p>
<details :open="s.phase==='baseline'" v-for="s in analysis.result.series" :key="s.target+s.protocol+s.phase"><summary>{{names[s.phase]||s.phase}} · {{s.protocol.toUpperCase()}} · {{s.target}}</summary><div class="scroll"><table><thead><tr><th>Skok</th><th>Router</th><th>Odpowiedzi</th><th>Strata</th><th>P50 / P95</th></tr></thead><tbody><tr v-for="(h,k) in s.stats" :key="k"><td>{{k}}</td><td>{{h.responders.join(', ')||'—'}}</td><td>{{h.rcv}} / {{h.snt}}</td><td>{{number(h.loss_pct)}}%</td><td>{{number(h.p50)}} / {{number(h.p95)}} ms</td></tr></tbody></table></div></details></template>
<details @toggle="($event.target as HTMLDetailsElement).open && !raw.length && loadRaw(0)"><summary>Surowe próbki MTR</summary>
<p v-if="rawError" role="alert">{{rawError}}</p><p v-else-if="rawBusy">Pobieranie próbek…</p><p v-else-if="!raw.length">Brak zapisanych próbek.</p>
<div v-if="raw.length" class="scroll"><table><thead><tr><th>Faza</th><th>Próba / skok</th><th>Router</th><th>RTT</th><th>Status</th></tr></thead><tbody><tr v-for="(s,i) in raw" :key="i"><td>{{names[s.phase]||s.phase}}</td><td>{{s.attempt}} / {{s.ttl}}</td><td>{{s.responder||'—'}}</td><td>{{number(s.rtt_ms)}} ms</td><td>{{s.status}}</td></tr></tbody></table></div>
<div class="pager" v-if="rawOffset||rawMore"><button class="quiet" :disabled="!rawOffset||rawBusy" @click="loadRaw(rawOffset-64)">Poprzednie próbki</button><button class="quiet" :disabled="!rawMore||rawBusy" @click="loadRaw(rawOffset+64)">Następne próbki</button></div></details>
<InventoryReport v-if="inventory" :inventory="inventory" :endpoint="transfer?.throughput.reservation_local_ip" />
<p v-else>Brak inwentaryzacji komputera i sieci w tej sesji.</p>
<details v-if="admin && inventory"><summary>Surowa inwentaryzacja Windows</summary><pre>{{JSON.stringify(inventory,null,2)}}</pre></details>
<div class="actions"><button class="quiet" @click="printReport">Drukuj / zapisz PDF</button><button class="quiet" @click="exportJson">Pobierz raport JSON</button></div>
</template></article>
</template></main><footer><span>VIP-NET Internet Diagnostics</span><span>Wersja 0.5.3</span></footer>
</template>
