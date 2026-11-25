<script lang="ts">
export type Finding={rule_id:string;version:string;severity:string;confidence:string;evidence:Record<string,unknown>;limitations:string;recommended_tests:string[]}
</script>
<script setup lang="ts">
defineProps<{items:Finding[];stats?:Record<string,{responders:string[]}>}>()
const titles:Record<string,string>={
 'sample.insufficient':'Za mało prób, by ocenić trasę','destination.missing_replies':'Część prób do celu pozostała bez odpowiedzi',
 'destination.unreachable':'Otrzymano komunikaty o nieosiągalności celu','destination.unconfirmed':'Nie potwierdzono odpowiedzi celu',
 'loss.persistent_to_target':'Braki odpowiedzi w tych samych rundach utrzymywały się aż do celu',
 'hop.silent':'Router po drodze milczał, a cel odpowiadał','hop.possible_icmp_limiting':'Router odpowiadał wybiórczo, a cel odpowiadał we wszystkich rundach',
 'latency.isolated_hop':'Dłuższy czas odpowiedzi jednego routera','latency.sustained_step':'Wzrost opóźnienia utrzymał się na dalszej trasie',
 'lan.possible_delay':'Możliwe opóźnienie blisko komputera','route.multiple_responders':'Na tym samym etapie odpowiadało kilka adresów',
 'route.change':'W trakcie prób zmieniły się adresy na trasie','route.possible_ecmp':'Próby mogły podążać różnymi drogami',
 'route.possible_loop':'W kilku rundach powtarzały się te same routery','ipv6.local_route':'Windows zgłosił problem z lokalną trasą IPv6',
 'boundary.possible_delay':'Opóźnienie przy przejściu między sieciami','protocol.divergence':'Próby ICMP i TCP dały różne wyniki',
 'load.possible_bufferbloat':'Pod obciążeniem odpowiedzi wracały później'}
const levels:Record<string,string>={warning:'ostrzeżenie',info:'informacja',high:'wysoka',medium:'średnia',low:'niska',critical:'krytyczne'}
function location(f:Finding){const e=f.evidence;return e.from_ttl!=null?'Od etapu '+e.from_ttl+' do '+e.end_ttl:e.ttl!=null?'Etap '+e.ttl:''}
</script>
<template><div v-for="(f,index) in items" :key="index"><p><strong>{{titles[f.rule_id]||f.rule_id}}</strong>
<span v-if="location(f)"> · {{location(f)}} <span v-if="stats?.[String(f.evidence.from_ttl??f.evidence.ttl)]?.responders.length">({{stats[String(f.evidence.from_ttl??f.evidence.ttl)].responders.join(', ')}})</span></span>
<br>{{f.limitations}} {{f.recommended_tests.join(' ')}}</p>
<details><summary>Podstawa wniosku · {{f.rule_id}}</summary><p>Reguła {{f.rule_id}}, wersja {{f.version}} · {{levels[f.severity]||f.severity}} · pewność {{levels[f.confidence]||f.confidence}}.</p><pre>{{JSON.stringify(f.evidence,null,2)}}</pre></details>
</div></template>
