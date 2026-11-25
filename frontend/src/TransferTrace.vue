<script lang="ts">
export type CounterTrace = {session_id:string;download:[number,number][];upload:[number,number][]}
</script>
<script setup lang="ts">
import {computed} from 'vue'
const props=defineProps<{trace?:CounterTrace;session:string}>()
const charts=computed(()=> (['download','upload'] as const).map(direction=>{
  const rows=props.trace?.session_id.toLowerCase()===props.session.toLowerCase()?props.trace[direction]:[]
  const points=rows.slice(1).map(([elapsed,bytes],i)=>({
    seconds:elapsed/1000, speed:(bytes-rows[i][1])*0.008/(elapsed-rows[i][0])
  }))
  const peak=Math.max(0,...points.map(p=>p.speed))
  const end=points[points.length-1]?.seconds||0
  const coordinates=points.map(p=>`${6+388*p.seconds/end},${75-70*p.speed/(peak||1)}`).join(' ')
  return {label:direction==='download'?'Pobieranie':'Wysyłanie',points,peak,end,coordinates}
}))
function fmt(n:number){return n.toLocaleString('pl-PL',{maximumFractionDigits:1})}
</script>
<template>
<section>
  <h3>Przebieg transferu</h3>
  <p v-if="!charts.some(c=>c.points.length)">Ten zapis nie zawiera próbek chwilowej prędkości.</p>
  <div v-else class="metrics">
    <section v-for="c in charts" :key="c.label">
      <h4>{{c.label}}</h4>
      <template v-if="c.points.length">
        <svg viewBox="0 0 400 80" role="img" :aria-label="c.label+' w czasie, maksimum '+fmt(c.peak)+' Mb/s'">
          <path d="M6 5H394 M6 40H394 M6 75H394" stroke="#e0e0e0" fill="none"/>
          <polyline :points="c.coordinates" fill="none" stroke="#0067c0" stroke-width="1.5"/>
          <circle v-for="p in c.points" :key="p.seconds" :cx="6+388*p.seconds/c.end" :cy="75-70*p.speed/(c.peak||1)" r="3" fill="transparent"><title>{{fmt(p.seconds)}} s · {{fmt(p.speed)}} Mb/s</title></circle>
        </svg>
        <p>0–{{fmt(c.end)}} s · Maksimum próbek {{fmt(c.peak)}} Mb/s</p>
        <details><summary>Wartości próbek</summary>
          <div class="scroll"><table><thead><tr><th>Czas od początku (s)</th><th>Prędkość (Mb/s)</th></tr></thead>
          <tbody><tr v-for="p in c.points" :key="p.seconds"><td>{{fmt(p.seconds)}}</td><td>{{fmt(p.speed)}}</td></tr></tbody></table></div>
        </details>
      </template>
      <p v-else>Brak próbek dla tego kierunku.</p>
    </section>
  </div>
</section>
</template>
