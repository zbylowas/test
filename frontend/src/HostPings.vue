<script lang="ts">
type Probe={at:string;status:string;rtt_ms:number|null;responder:string|null;native_code:number}
type Host={target:string|null;planned:number;timeout_ms:number;reason:string|null;samples:Probe[]}
export type HostMeasurements={gateway:Host;node:Host}
</script>
<script setup lang="ts">
import {computed} from 'vue'
const props=defineProps<{hosts?:HostMeasurements;node:string|null}>()
const labels:Record<string,string>={echo_reply:'Cel odpowiedział',timeout:'Minął czas oczekiwania',unavailable:'Błąd lokalnego pomiaru',unreachable:'Zgłoszono nieosiągalność',ttl_expired:'Odpowiedział router pośredni',other_responder:'Odpowiedział inny adres'}
const reasons:Record<string,string>={no_reservation:'Nie zestawiono połączenia z węzłem.',no_separate_gateway:'Windows nie wskazał osobnego routera na tej trasie.',route_changed:'Połączenie zmieniło się po rezerwacji.',cancelled:'Użytkownik zatrzymał test.',interrupted:'Zapis zakończył się przed ukończeniem serii.',invalid_gateway:'Adres routera nie spełnił warunków pomiaru.',route_lookup_failed:'Windows nie udostępnił trasy.',missing_interface_scope:'Brakuje numeru karty dla lokalnego IPv6.'}
const rows=computed(()=>props.hosts ? (['gateway','node'] as const).map(role=>{
  const h=props.hosts![role]
  const times=h.samples.filter(s=>s.status==='echo_reply'&&s.responder===h.target&&s.rtt_ms!=null).map(s=>s.rtt_ms!)
  const local=h.samples.filter(s=>s.status==='unavailable').length
  return {h, name:role==='gateway'?'Router na drodze do internetu':('Serwer pomiarowy '+(props.node||'')), times, mean:times.length?times.reduce((a,b)=>a+b,0)/times.length:null,
    sent:h.samples.length-local, local, timeout:h.samples.filter(s=>s.status==='timeout').length}
}) : [])
function fmt(n:number){return n.toLocaleString('pl-PL',{maximumFractionDigits:1})}
</script>
<template><section><h3>Ping do routera i serwera</h3>
<p v-if="!hosts">Ten zapis nie zawiera oddzielnych prób ping. Pomiary trasy znajdziesz poniżej.</p>
<template v-else><p>Po teście prędkości komputer wysyła krótkie wiadomości ICMP. Ping to czas od wysłania wiadomości do powrotu odpowiedzi. Niższa wartość oznacza szybszą odpowiedź.</p>
<div v-for="r in rows" :key="r.name"><h4>{{r.name}} <span v-if="r.h.target">· {{r.h.target}}</span></h4>
<p><strong>{{r.mean==null?'Brak czasu odpowiedzi':fmt(r.mean)+' ms średnio'}}</strong>. Odpowiedzi celu {{r.times.length}} z {{r.sent}} wysłanych prób. Bez odpowiedzi w ciągu {{r.h.timeout_ms}} ms: {{r.timeout}}.<span v-if="r.local"> Windows nie wykonał {{r.local}} prób.</span> <span v-if="r.h.reason">{{reasons[r.h.reason]||'Pomiar niepełny.'}}</span></p>
<details v-if="r.h.samples.length"><summary>Poszczególne próby · {{r.name}}</summary>
<div class="scroll"><table><thead><tr><th>Próba</th><th>Czas UTC</th><th>Wynik</th><th>Adres odpowiedzi</th><th>Ping</th><th>Kod Windows</th></tr></thead>
<tbody><tr v-for="(s,i) in r.h.samples" :key="i"><td>{{i+1}}</td><td>{{s.at}}</td><td>{{labels[s.status]||s.status}}</td><td>{{s.responder||'—'}}</td><td>{{s.rtt_ms==null?'—':fmt(s.rtt_ms)+' ms'}}</td><td>{{s.native_code}}</td></tr></tbody></table></div></details>
</div></template></section></template>
