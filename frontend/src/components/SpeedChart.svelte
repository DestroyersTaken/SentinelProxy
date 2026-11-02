<script lang="ts">
  import type { Point } from "../lib/types";
  import { speed, clock } from "../lib/format";

  let { points = [], height = 180, span = 120 }: { points?: Point[]; height?: number; span?: number } = $props();
  let width = $state(600);
  let el: HTMLDivElement;
  let hover = $state<number | null>(null);

  $effect(() => {
    const ro = new ResizeObserver(([e]) => (width = Math.max(200, e.contentRect.width)));
    ro.observe(el);
    return () => ro.disconnect();
  });

  const data = $derived.by(() => {
    const p = points.slice(-span);
    const pad = span - p.length;
    return { p, pad };
  });
  const max = $derived(Math.max(1024, ...data.p.map((x) => Math.max(x.up, x.down))) * 1.15);
  const step = $derived(width / (span - 1));
  const x = (i: number) => (i + data.pad) * step;
  const y = (v: number) => height - 18 - (v / max) * (height - 30);

  function path(key: "up" | "down", close: boolean) {
    if (!data.p.length) return "";
    let d = `M${x(0)},${y(data.p[0][key])}`;
    for (let i = 1; i < data.p.length; i++) {
      const x0 = x(i - 1), x1 = x(i), y0 = y(data.p[i - 1][key]), y1 = y(data.p[i][key]);
      const cx = (x0 + x1) / 2;
      d += ` C${cx},${y0} ${cx},${y1} ${x1},${y1}`;
    }
    if (close) d += ` L${x(data.p.length - 1)},${height - 18} L${x(0)},${height - 18} Z`;
    return d;
  }

  function move(e: MouseEvent) {
    const r = el.getBoundingClientRect();
    const i = Math.round((e.clientX - r.left) / step) - data.pad;
    hover = i >= 0 && i < data.p.length ? i : null;
  }
  const grid = $derived([0.25, 0.5, 0.75, 1].map((f) => ({ v: (max / 1.15) * f, yy: y((max / 1.15) * f) })));
</script>

<!-- svelte-ignore a11y_no_static_element_interactions -->
<div class="sc" bind:this={el} onmousemove={move} onmouseleave={() => (hover = null)} style="height:{height}px">
  <svg {width} {height}>
    <defs>
      <linearGradient id="gd" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="var(--down)" stop-opacity=".35" /><stop offset="1" stop-color="var(--down)" stop-opacity="0" /></linearGradient>
      <linearGradient id="gu" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="var(--up)" stop-opacity=".28" /><stop offset="1" stop-color="var(--up)" stop-opacity="0" /></linearGradient>
    </defs>
    {#each grid as g}
      <line x1="0" x2={width} y1={g.yy} y2={g.yy} stroke="var(--border)" stroke-dasharray="3 4" />
      <text x="4" y={g.yy - 4} class="lbl">{speed(g.v)}</text>
    {/each}
    <line x1="0" x2={width} y1={height - 18} y2={height - 18} stroke="var(--border-2)" />
    <text x={width - 4} y={height - 4} class="lbl" text-anchor="end">now</text>
    <text x="4" y={height - 4} class="lbl">{Math.round(span / 60)} min ago</text>
    <path d={path("down", true)} fill="url(#gd)" />
    <path d={path("up", true)} fill="url(#gu)" />
    <path d={path("down", false)} fill="none" stroke="var(--down)" stroke-width="1.8" />
    <path d={path("up", false)} fill="none" stroke="var(--up)" stroke-width="1.8" />
    {#if hover !== null}
      <line x1={x(hover)} x2={x(hover)} y1="0" y2={height - 18} stroke="var(--border-2)" />
      <circle cx={x(hover)} cy={y(data.p[hover].down)} r="3.5" fill="var(--down)" />
      <circle cx={x(hover)} cy={y(data.p[hover].up)} r="3.5" fill="var(--up)" />
    {/if}
  </svg>
  {#if hover !== null}
    {@const pt = data.p[hover]}
    <div class="tip" style="left:{Math.min(x(hover) + 10, width - 150)}px">
      <div class="muted">{clock(pt.t * 1000)}</div>
      <div><span class="sw" style="background:var(--down)"></span>↓ {speed(pt.down)}</div>
      <div><span class="sw" style="background:var(--up)"></span>↑ {speed(pt.up)}</div>
    </div>
  {/if}
</div>

<style>
  .sc { position: relative; width: 100%; }
  svg { display: block; overflow: visible; }
  .lbl { font-size: 10.5px; fill: var(--faint); font-variant-numeric: tabular-nums; }
  .tip { position: absolute; top: 6px; background: var(--surface-2); border: 1px solid var(--border-2); border-radius: 8px; padding: 6px 9px; font-size: 12px; pointer-events: none; box-shadow: var(--shadow); white-space: nowrap; font-variant-numeric: tabular-nums; }
  .sw { display: inline-block; width: 8px; height: 8px; border-radius: 2px; margin-right: 5px; }
</style>
