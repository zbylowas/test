<script lang="ts">
export type Reading<T> = {status:'ok'|'partial'|'unavailable'; value?:T; reason?:string; total?:number}
type Adapter = {
  id:string; index:number; type:number; oper_status:number; model:Reading<string>; driver:Reading<string>; mtu:number;
  unicast:Reading<{ip:string;prefix_length:number}[]>; gateways:Reading<string[]>; dns:Reading<string[]>;
  link:Reading<{rx_bps:number;tx_bps:number}>; counters:Reading<{rx_errors:number;tx_errors:number;rx_discards:number;tx_discards:number}>;
  traffic:Reading<{rx_bps:number;tx_bps:number}>
}
type Radio = {id:string; connection:Reading<{signal_pct:number;phy:number;rx_kbps:number;tx_kbps:number}>; channel:Reading<number>; rssi_dbm:Reading<number>}
export type Inventory = {
  system:{cpu_model:Reading<string>;memory:Reading<{total_bytes:number;available_bytes:number}>;logical_processors:number};
  interfaces:Reading<Adapter[]>; unique_neighbor_macs:Reading<number>; wifi:Reading<Radio[]>;
  neighbors:Reading<{index:number; mac_id:Reading<string>; vendor:Reading<string>}[]>;
  duplicate_addresses:Reading<unknown[]>; gateway_changes:Reading<unknown[]>
}
</script>
<script setup lang="ts">
import {computed} from 'vue'
const props=defineProps<{inventory:Inventory; endpoint?:Reading<string>}>()
const types:Record<number,string>={6:'Ethernet',71:'Wi-Fi',23:'PPP',24:'Loopback',131:'Tunel',243:'Sieć komórkowa',244:'Sieć komórkowa'}
const standards:Record<number,string>={4:'802.11a',5:'802.11b',6:'802.11g',7:'802.11n',8:'802.11ac',9:'802.11ad',10:'802.11ax',11:'802.11be'}
const format=new Intl.NumberFormat('pl-PL',{maximumFractionDigits:2})
function missing(r?:Reading<unknown>){return r?.reason?'niedostępne ('+r.reason+')':'brak w zapisie'}
function measurement(n:number|undefined, r:Reading<unknown>, unit='', divisor=1){return n==null?missing(r):format.format(n/divisor)+unit}
function list(r:Reading<string[]>){return r.value ? (r.value.join(', ')||'brak wpisów')+(r.status==='partial'?' (lista częściowa)':'') : missing(r)}
function count(r:Reading<unknown[]>){return r.value ? String(r.value.length)+(r.status==='partial'?' (odczyt częściowy)':'') : missing(r)}
function medium(n:Adapter){return types[n.type]||('Typ interfejsu Windows '+n.type)}
const matches=computed(()=>(props.inventory.interfaces.value||[]).filter(n=>n.unicast.value?.some(a=>a.ip===props.endpoint?.value)))
const connection=computed(()=>{
  if(!props.endpoint?.value)return missing(props.endpoint)
  if(matches.value.length!==1)return matches.value.length?'niejednoznaczne dopasowanie adresu':'brak karty z adresem połączenia w odczycie Windows'
  return medium(matches.value[0])+' · '+(matches.value[0].model.value||missing(matches.value[0].model))
})
const neighbors=computed(()=>{
  const table=props.inventory.neighbors
  if(!table.value)return missing(table)
  const rows=table.value.filter(r=>r.index===matches.value[0]?.index)
  const count=new Set(rows.map(r=>r.mac_id.value).filter(Boolean)).size
  const vendors=[...new Set(rows.map(r=>r.vendor.value).filter(Boolean))].sort()
  return (table.status==='partial'?'co najmniej ':'')+count+(vendors.length?' · rozpoznani producenci: '+vendors.join(', '):'')
})
const active=computed(()=>(props.inventory.interfaces.value||[]).filter(n=>n.oper_status===1))
</script>
<template>
<section><h3>Komputer, LAN i Wi-Fi</h3>
<dl class="inventory-data">
  <dt>Typ połączenia przy rezerwacji HTTPS</dt><dd>{{connection}}</dd>
  <template v-if="matches.length===1"><dt>Sąsiedzi na karcie pomiarowej</dt><dd>{{neighbors}}</dd></template>
  <dt>Sąsiedzi widoczni dla Windows</dt><dd>{{measurement(inventory.unique_neighbor_macs.value,inventory.unique_neighbor_macs)}}<small>Unikalne adresy MAC w pamięci ARP/IPv6 wszystkich interfejsów. Mogą należeć m.in. do routerów, telefonów i urządzeń wirtualnych.</small></dd>
  <dt>Procesor</dt><dd>{{inventory.system.cpu_model.value||missing(inventory.system.cpu_model)}} · procesory logiczne {{inventory.system.logical_processors}}</dd>
  <dt>RAM</dt><dd>{{measurement(inventory.system.memory.value?.total_bytes,inventory.system.memory,' GiB',2**30)}} · dostępne {{measurement(inventory.system.memory.value?.available_bytes,inventory.system.memory,' GiB',2**30)}}</dd>
  <dt>Adresy zduplikowane według Windows</dt><dd>{{count(inventory.duplicate_addresses)}}</dd>
  <dt>Zmiany MAC bramy</dt><dd>{{count(inventory.gateway_changes)}}</dd>
</dl>
<p v-if="!inventory.wifi.value">{{missing(inventory.wifi)}}</p>
<p v-else-if="!inventory.wifi.value.length">Windows nie wykrył karty Wi-Fi.</p>
<p v-for="r in inventory.wifi.value" :key="r.id"><strong>Wi-Fi · {{inventory.interfaces.value?.find(n=>n.id.toLowerCase()===r.id.toLowerCase())?.model.value||r.id}}</strong><br>
Sygnał {{measurement(r.connection.value?.signal_pct,r.connection,'%')}} · RSSI {{measurement(r.rssi_dbm.value,r.rssi_dbm,' dBm')}} · kanał {{measurement(r.channel.value,r.channel)}} · {{r.connection.value ? standards[r.connection.value.phy]||('PHY '+r.connection.value.phy) : missing(r.connection)}}<br>
RX / TX {{measurement(r.connection.value?.rx_kbps,r.connection,' Mb/s',1000)}} / {{measurement(r.connection.value?.tx_kbps,r.connection,' Mb/s',1000)}}</p>
<details><summary>Aktywne interfejsy Windows</summary>
<p v-if="!active.length">{{inventory.interfaces.value?'Brak aktywnych w zapisanej liście.':missing(inventory.interfaces)}}</p>
<p v-if="inventory.interfaces.status==='partial'">Lista kart częściowa.</p>
<dl class="inventory-data" v-for="n in active" :key="n.id">
  <dt>{{medium(n)}} · karta</dt><dd>{{n.model.value||missing(n.model)}} · sterownik {{n.driver.value||missing(n.driver)}}</dd>
  <dt>Prędkość łącza RX / TX</dt><dd>{{measurement(n.link.value?.rx_bps,n.link,' Mb/s',1e6)}} / {{measurement(n.link.value?.tx_bps,n.link,' Mb/s',1e6)}}</dd>
  <dt>Ruch przed testem RX / TX</dt><dd>{{measurement(n.traffic.value?.rx_bps,n.traffic,' Mb/s',1e6)}} / {{measurement(n.traffic.value?.tx_bps,n.traffic,' Mb/s',1e6)}}</dd>
  <dt>Błędy RX / TX</dt><dd>{{measurement(n.counters.value?.rx_errors,n.counters)}} / {{measurement(n.counters.value?.tx_errors,n.counters)}}</dd>
  <dt>Odrzucenia RX / TX</dt><dd>{{measurement(n.counters.value?.rx_discards,n.counters)}} / {{measurement(n.counters.value?.tx_discards,n.counters)}}</dd>
  <dt>Adresy</dt><dd>{{n.unicast.value?.map(a=>a.ip+'/'+a.prefix_length).join(', ')|| (n.unicast.value?'brak wpisów':missing(n.unicast))}}</dd>
  <dt>Bramy</dt><dd>{{list(n.gateways)}}</dd><dt>DNS</dt><dd>{{list(n.dns)}}</dd><dt>MTU</dt><dd>{{n.mtu}}</dd>
</dl></details></section>
</template>
<style scoped>
.inventory-data{display:grid;grid-template-columns:minmax(9rem, 15rem) 1fr;gap:.45rem 1rem;margin:1rem 0}
dt{font-weight:600}dd{margin:0;overflow-wrap:anywhere}dd small{display:block}
@media(max-width:600px){.inventory-data{grid-template-columns:1fr;gap:.15rem}.inventory-data dd{margin-bottom:.5rem}}
</style>
