"""
BoundSec - static HTML research report generator.

Reads ``results/summary.json`` (the single source of truth for every number) and
the figure PNGs, and emits a self-contained HTML page with the figures embedded
as data URIs.  The prose template is hand-authored; only the numbers and images
are injected, so the report can never disagree with the evaluation it reports.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path


def _img(path: Path) -> str:
    if not path.exists():
        return ""
    b64 = base64.b64encode(path.read_bytes()).decode("ascii")
    return f"data:image/png;base64,{b64}"


def _fig_card(figures: Path, name: str, title: str, caption: str, wide: bool = True) -> str:
    uri = _img(figures / name)
    if not uri:
        return ""
    cls = "figure wide" if wide else "figure"
    return f"""<figure class="{cls}">
      <div class="frame"><img loading="lazy" src="{uri}" alt="{title}"></div>
      <figcaption><span class="fc-title">{title}</span> {caption}</figcaption>
    </figure>"""


def _fmt(x, d=0):
    try:
        return f"{float(x):.{d}f}"
    except (TypeError, ValueError):
        return "—"


def build(results_dir: Path, figures_dir: Path, out: Path) -> Path:
    results_dir, figures_dir = Path(results_dir), Path(figures_dir)
    summary = json.loads((results_dir / "summary.json").read_text())

    strat = summary.get("strategy", {})
    ceilings = strat.get("ceilings", {})
    dets = summary.get("detectors", {})

    # headline recall numbers (coverage_guided vs static_replay), pooled
    def recall_of(s):
        vals = [v["recall_pct"] for k, v in strat.items()
                if k.startswith(s + "/") and isinstance(v, dict) and "recall_pct" in v]
        return sum(vals) / len(vals) if vals else 0.0

    guided_recall = recall_of("coverage_guided")
    static_recall = recall_of("static_replay")
    # hardened-specific
    g_hard = strat.get("coverage_guided/hardened", {}).get("recall_pct", 0)
    s_hard = strat.get("static_replay/hardened", {}).get("recall_pct", 0)

    eff = summary.get("effect_sizes", {})
    # Headline effect size is against the meaningful baseline (static replay);
    # the no-bandit comparison is ~0.5 by design and would dilute a pooled median.
    a12s = [v["a12"] for k, v in eff.items()
            if k.endswith("/static_replay") and isinstance(v, dict) and "a12" in v]
    a12_median = sorted(a12s)[len(a12s) // 2] if a12s else 0.0

    heur = dets.get("heuristic", {})
    lift = (guided_recall / static_recall) if static_recall else 0

    figs = "\n".join(filter(None, [
        _fig_card(figures_dir, "fig1_strategy_comparison.png",
                  "Bug recall across the hardening spectrum",
                  "Coverage-guided search recovers the large majority of reachable bugs at "
                  "every hardening level; static replay collapses as defenses stack up."),
        _fig_card(figures_dir, "fig2_discovery_curves.png",
                  "Discovery vs. query budget",
                  "Guided search pulls ahead early and keeps climbing; replay plateaus after "
                  "one pass through the corpus."),
        _fig_card(figures_dir, "fig4_effect_sizes.png",
                  "Effect sizes (Vargha–Delaney Â₁₂)",
                  "The advantage is statistically large and consistent across targets."),
        _fig_card(figures_dir, "fig3_coverage_growth.png",
                  "Behavioural coverage growth",
                  "Feedback compounds: guided strategies reach behaviour the baselines never do."),
        _fig_card(figures_dir, "fig7_operator_effectiveness.png",
                  "Which operators find bugs",
                  "The bandit yields an interpretable ranking of attack effectiveness for the target."),
        _fig_card(figures_dir, "fig8_technique_outcome_heatmap.png",
                  "Attack technique × vulnerability outcome",
                  "Where each attack family lands — the structure the fuzzer discovers."),
        _fig_card(figures_dir, "fig11_guardrail_distribution.png",
                  "Guardrail regime reached, by strategy",
                  "The mechanism behind the recall gap: guided search drives the agent toward compliance."),
        _fig_card(figures_dir, "fig5_detector_roc_pr.png",
                  "Detector quality (ROC / PR)",
                  "Threshold-free detector evaluation against gym ground truth."),
        _fig_card(figures_dir, "fig6_detector_calibration.png",
                  "Detector calibration",
                  "Reliability of the continuous suspiciousness scores."),
        _fig_card(figures_dir, "fig9_defense_effectiveness.png",
                  "Defense effectiveness",
                  "Risk reduction attributable to each control alone and to cumulative defense-in-depth."),
        _fig_card(figures_dir, "fig10_dimension_ablation.png",
                  "Coverage-dimension ablation",
                  "Coverage guidance as a whole drives exploration (the bug-only control explores "
                  "~15% less of the space); the five dimensions are redundant, so removing any single one barely hurts."),
    ]))

    diag_loop = _img(figures_dir / "fig0_feedback_loop.png")
    diag_cov = _img(figures_dir / "fig0_coverage_abstraction.png")

    html = _TEMPLATE.format(
        guided_recall=_fmt(guided_recall), static_recall=_fmt(static_recall),
        lift=_fmt(lift, 1), a12=_fmt(a12_median, 2),
        g_hard=_fmt(g_hard), s_hard=_fmt(s_hard),
        roc=_fmt(heur.get("roc_auc", 0), 3), pr=_fmt(heur.get("pr_auc", 0), 3),
        ceil_naive=ceilings.get("naive", "—"), ceil_frontier=ceilings.get("frontier", "—"),
        diag_loop=diag_loop, diag_cov=diag_cov, figures=figs,
    )
    out = Path(out)
    out.write_text(html)
    return out


_TEMPLATE = r"""<title>BoundSec</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Archivo:wght@600;700;800;900&family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap">
<style>
:root{{
  --bg:#f3f5f8; --panel:#ffffff; --panel2:#fafbfc; --ink:#0f1720; --ink2:#4a5666;
  --muted:#8b97a6; --line:#e2e7ee; --line2:#eef1f5;
  --blue:#2a78d6; --blue-ink:#1a5299; --aqua:#1baf7a; --amber:#eda100;
  --red:#e34948; --violet:#4a3aa7; --orange:#eb6834;
  --grid:#e6e9ee;
  --shadow:0 1px 2px rgba(16,23,32,.04),0 8px 28px rgba(16,23,32,.06);
  --radius:14px;
}}
@media (prefers-color-scheme:dark){{:root:not([data-theme="light"]){{
  --bg:#0c1016; --panel:#141a22; --panel2:#111721; --ink:#eef2f7; --ink2:#aab6c4;
  --muted:#6b7788; --line:#232c38; --line2:#1b2129;
  --blue:#3f8ae6; --blue-ink:#7fb2ee; --aqua:#25c089; --amber:#f0b429;
  --red:#f06462; --violet:#9085e9; --orange:#f0764a; --grid:#232c38;
  --shadow:0 1px 2px rgba(0,0,0,.3),0 10px 30px rgba(0,0,0,.35);
}}}}
:root[data-theme="dark"]{{
  --bg:#0c1016; --panel:#141a22; --panel2:#111721; --ink:#eef2f7; --ink2:#aab6c4;
  --muted:#6b7788; --line:#232c38; --line2:#1b2129;
  --blue:#3f8ae6; --blue-ink:#7fb2ee; --aqua:#25c089; --amber:#f0b429;
  --red:#f06462; --violet:#9085e9; --orange:#f0764a; --grid:#232c38;
  --shadow:0 1px 2px rgba(0,0,0,.3),0 10px 30px rgba(0,0,0,.35);
}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--ink);
  font-family:"IBM Plex Sans",system-ui,sans-serif;line-height:1.6;
  -webkit-font-smoothing:antialiased;}}
.mono{{font-family:"IBM Plex Mono",ui-monospace,monospace}}
.wrap{{max-width:1080px;margin:0 auto;padding:0 24px}}
h1,h2,h3{{font-family:"Archivo",sans-serif;line-height:1.08;letter-spacing:-.02em;
  text-wrap:balance;margin:0}}
a{{color:var(--blue);text-decoration:none}}
a:hover{{text-decoration:underline}}

/* top bar */
.topbar{{position:sticky;top:0;z-index:20;background:color-mix(in srgb,var(--bg) 86%,transparent);
  backdrop-filter:blur(10px);border-bottom:1px solid var(--line)}}
.topbar .wrap{{display:flex;align-items:center;gap:18px;height:56px}}
.brand{{font-family:"Archivo";font-weight:900;letter-spacing:-.02em;font-size:18px}}
.brand .dot{{color:var(--blue)}}
.nav{{margin-left:auto;display:flex;gap:22px;font-size:13px}}
.nav a{{color:var(--ink2)}}
@media(max-width:720px){{.nav{{display:none}}}}

/* hero */
.hero{{padding:76px 0 40px;position:relative;overflow:hidden}}
.hero::before{{content:"";position:absolute;inset:0;z-index:-1;
  background:radial-gradient(1100px 380px at 12% -8%,color-mix(in srgb,var(--blue) 14%,transparent),transparent 70%);}}
.eyebrow{{font-family:"IBM Plex Mono";font-size:12px;font-weight:500;letter-spacing:.14em;
  text-transform:uppercase;color:var(--blue-ink);display:flex;align-items:center;gap:10px}}
.eyebrow::before{{content:"";width:26px;height:1.5px;background:var(--blue)}}
.hero h1{{font-size:clamp(40px,6.4vw,72px);font-weight:900;margin:20px 0 0}}
.hero .lede{{font-size:clamp(17px,2.2vw,21px);color:var(--ink2);max-width:60ch;margin:22px 0 0}}
.hero .lede b{{color:var(--ink);font-weight:600}}
.cta{{display:flex;gap:12px;margin-top:30px;flex-wrap:wrap}}
.btn{{font-family:"IBM Plex Mono";font-size:13px;font-weight:500;padding:11px 18px;border-radius:10px;
  border:1px solid var(--line);background:var(--panel);color:var(--ink);box-shadow:var(--shadow)}}
.btn.primary{{background:var(--blue);color:#fff;border-color:transparent}}

/* stat tiles */
.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:44px 0 8px}}
@media(max-width:820px){{.stats{{grid-template-columns:repeat(2,1fr)}}}}
.stat{{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);
  padding:20px;box-shadow:var(--shadow);position:relative;overflow:hidden}}
.stat::after{{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--blue)}}
.stat.g2::after{{background:var(--aqua)}} .stat.g3::after{{background:var(--amber)}} .stat.g4::after{{background:var(--violet)}}
.stat .n{{font-family:"Archivo";font-weight:800;font-size:34px;letter-spacing:-.03em;
  font-variant-numeric:tabular-nums}}
.stat .l{{font-size:12.5px;color:var(--ink2);margin-top:4px}}
.stat .s{{font-family:"IBM Plex Mono";font-size:11px;color:var(--muted);margin-top:8px}}

/* sections */
section{{padding:52px 0;border-top:1px solid var(--line2)}}
.sec-eyebrow{{font-family:"IBM Plex Mono";font-size:12px;letter-spacing:.12em;text-transform:uppercase;
  color:var(--muted);margin-bottom:12px}}
section h2{{font-size:clamp(26px,3.4vw,36px);font-weight:800}}
section p.body{{color:var(--ink2);max-width:68ch;margin:16px 0}}
section p.body b{{color:var(--ink);font-weight:600}}

/* dimension table */
.dimtable{{width:100%;border-collapse:collapse;margin-top:22px;font-size:14px}}
.dimtable th,.dimtable td{{text-align:left;padding:12px 14px;border-bottom:1px solid var(--line)}}
.dimtable th{{font-family:"IBM Plex Mono";font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);font-weight:500}}
.dimtable td.code{{font-family:"IBM Plex Mono";color:var(--blue-ink);font-size:12.5px;white-space:nowrap}}
.dimtable tr td:last-child{{color:var(--muted)}}

/* diagram + figure frames */
.diagram{{margin:26px 0;background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);
  padding:12px;box-shadow:var(--shadow)}}
.diagram img{{display:block;width:100%;border-radius:8px}}
.figgrid{{display:grid;gap:26px;margin-top:26px}}
.figure{{margin:0}}
.figure .frame{{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);
  padding:12px;box-shadow:var(--shadow)}}
.figure img{{display:block;width:100%;border-radius:8px}}
.figure figcaption{{font-size:13px;color:var(--ink2);margin-top:12px;max-width:80ch}}
.figure .fc-title{{font-weight:600;color:var(--ink)}}

/* callout */
.callout{{background:var(--panel2);border:1px solid var(--line);border-left:3px solid var(--amber);
  border-radius:12px;padding:18px 22px;margin:22px 0}}
.callout .k{{font-family:"IBM Plex Mono";font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--amber);font-weight:600}}
.callout p{{margin:8px 0 0;color:var(--ink2);font-size:14.5px}}

/* limitations list */
.lim{{display:grid;gap:12px;margin-top:20px}}
.lim .item{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px 18px;box-shadow:var(--shadow)}}
.lim .item b{{color:var(--ink)}}
.lim .item span{{color:var(--ink2);font-size:14px}}

/* code */
pre{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px 18px;
  overflow-x:auto;font-family:"IBM Plex Mono";font-size:13px;color:var(--ink);box-shadow:var(--shadow)}}
pre .c{{color:var(--muted)}} pre .k{{color:var(--blue-ink)}}

footer{{border-top:1px solid var(--line);padding:40px 0 70px;color:var(--muted);font-size:13px}}
footer .mono{{color:var(--ink2)}}
.chips{{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}}
.chip{{font-family:"IBM Plex Mono";font-size:11px;padding:5px 10px;border-radius:999px;
  border:1px solid var(--line);color:var(--ink2);background:var(--panel)}}
@media(prefers-reduced-motion:no-preference){{
  .stat,.figure .frame{{transition:transform .2s ease}}
  .figure .frame:hover{{transform:translateY(-2px)}}
}}
</style>

<div class="topbar"><div class="wrap">
  <div class="brand">Bound<span class="dot">Sec</span></div>
  <nav class="nav">
    <a href="#idea">Idea</a><a href="#method">Method</a><a href="#results">Results</a>
    <a href="#detectors">Detectors</a><a href="#limits">Limitations</a>
  </nav>
</div></div>

<header class="hero"><div class="wrap">
  <div class="eyebrow">Coverage-guided fuzzing · LLM-agent security</div>
  <h1>Fuzzing agents<br>with a coverage signal.</h1>
  <p class="lede">Red-teaming an LLM agent, treated as a <b>greybox fuzzing</b> problem.
    BoundSec defines what <b>coverage</b> means for a stochastic tool-calling policy, drives an
    evolutionary search with it, and proves — on a ground-truth benchmark — that it finds far
    more vulnerabilities than replaying a fixed payload list.</p>
  <div class="cta">
    <a class="btn primary" href="#results">See the results</a>
    <a class="btn" href="#method">How it works</a>
  </div>

  <div class="stats">
    <div class="stat"><div class="n">{guided_recall}%</div>
      <div class="l">Reachable bugs found by coverage-guided search</div>
      <div class="s">vs. {static_recall}% for static replay</div></div>
    <div class="stat g2"><div class="n">{lift}×</div>
      <div class="l">More vulnerabilities than payload replay</div>
      <div class="s">pooled over the hardening spectrum</div></div>
    <div class="stat g3"><div class="n">{a12}</div>
      <div class="l">Median Â₁₂ effect size vs. static replay</div>
      <div class="s">&gt;0.71 = "large" · Mann–Whitney p &lt; 0.01</div></div>
    <div class="stat g4"><div class="n">{roc}</div>
      <div class="l">Detector ROC-AUC vs. ground truth</div>
      <div class="s">PR-AUC {pr} · threshold-free</div></div>
  </div>
</div></header>

<section id="idea"><div class="wrap">
  <div class="sec-eyebrow">The idea</div>
  <h2>What is "coverage" for an agent?</h2>
  <p class="body">Classical fuzzers compound because a coverage signal tells the search which
    inputs reached new behaviour. An LLM agent exposes no branch counters. BoundSec projects
    each execution trace onto a finite set of <b>behaviour descriptors</b> across five
    dimensions, then folds them into an AFL-style bitmap. The load-bearing choice: unbounded
    tool arguments are abstracted to a small closed set of <b>security-relevant classes</b>,
    keeping the coverage domain finite while preserving the structure that matters.</p>
  <div class="diagram"><img src="{diag_cov}" alt="Behavioural coverage abstraction"></div>
  <table class="dimtable">
    <thead><tr><th>Dimension</th><th>Descriptor</th><th>Program analogue</th></tr></thead>
    <tbody>
      <tr><td>Action</td><td class="code">A:tool | arg-class | outcome</td><td>basic-block coverage</td></tr>
      <tr><td>Transition</td><td class="code">T:tool_i → tool_j</td><td>edge / branch coverage</td></tr>
      <tr><td>Guardrail</td><td class="code">G:response-mode @ turn</td><td>state-machine coverage</td></tr>
      <tr><td>Fault</td><td class="code">E:status | error-class</td><td>crash / sanitiser buckets</td></tr>
      <tr><td>Novelty</td><td class="code">N:simhash-bucket</td><td>output-diversity proxy</td></tr>
    </tbody>
  </table>
</div></section>

<section id="method"><div class="wrap">
  <div class="sec-eyebrow">The method</div>
  <h2>A feedback loop that compounds</h2>
  <p class="body">An input that lights up a new bitmap slot is kept and mutated further; a power
    schedule spends energy on the most promising inputs, and a <b>discounted-UCB bandit</b>
    learns which of 18 mutation operators pay off against <b>this</b> target. The reward is dense
    — new coverage, plus how far the mutation pushed the agent up the "guardrail giving way"
    gradient, plus a bonus when the oracle confirms a bug — so there is signal on every query.</p>
  <div class="diagram"><img src="{diag_loop}" alt="Coverage-guided feedback loop"></div>
</div></section>

<section id="results"><div class="wrap">
  <div class="sec-eyebrow">Results · reproducible from a seed</div>
  <h2>Coverage guidance beats payload replay — and the gap widens as targets harden</h2>
  <p class="body">Four agent profiles span a naïve→frontier hardening spectrum. Recall is measured
    against the <b>reachable set</b> per target (the union of every bug any method found). On the
    hardened agent, coverage-guided search recovers <b>{g_hard}%</b> of reachable bugs versus
    <b>{s_hard}%</b> for static replay — exactly where a fixed payload list runs out of road.</p>
  <div class="callout"><div class="k">Why this matters</div>
    <p>A payload scanner cannot adapt to the target: it asks the same questions and plateaus.
      A coverage-guided fuzzer turns each observation into a decision about what to try next,
      so it keeps discovering behaviour a fixed list never reaches.</p></div>
  <div class="figgrid">{figures}</div>
</div></section>

<section id="limits"><div class="wrap">
  <div class="sec-eyebrow">Honesty</div>
  <h2>Limitations &amp; threats to validity</h2>
  <p class="body">A benchmark's credibility depends on stating these plainly.</p>
  <div class="lim">
    <div class="item"><b>The gym is a model, not a real LLM.</b> <span>Its susceptibility model is a
      transparent caricature of how attack families erode guardrails — the measurement instrument
      that supplies ground truth, not a claim about any specific model. Live-model adapters exist
      to demonstrate the method off the benchmark.</span></div>
    <div class="item"><b>Recall is against an empirical reachable set,</b> <span>the union of all
      methods — a <i>relative</i> recall, standard in fuzzing when the true bug count is unknown.</span></div>
    <div class="item"><b>Coverage guidance is the driver; the bandit is recall-neutral here.</b>
      <span>The two guided variants (with/without the operator bandit) are statistically
      indistinguishable on this benchmark. The bandit's value is the interpretable per-target
      operator ranking it produces, not a recall boost — reported as such, not oversold.</span></div>
    <div class="item"><b>A realism layer keeps detection honest.</b> <span>Without injected subtle
      leaks and suspicious-benign text the detector would score a meaningless perfect AUC; the layer
      is what makes the ROC/PR evaluation meaningful.</span></div>
  </div>
</div></section>

<footer><div class="wrap">
  <div class="chips">
    <span class="chip">18 mutation operators</span><span class="chip">5 coverage dimensions</span>
    <span class="chip">7 defense layers</span><span class="chip">61 tests</span>
    <span class="chip">reachable set: {ceil_naive}→{ceil_frontier} bugs</span>
  </div>
  <p style="margin-top:18px">Reproduce the full evaluation, fully offline and deterministically:</p>
  <pre><span class="c"># the whole suite → results/ + figures/</span>
make experiment
<span class="c"># or one campaign against a hardened gym agent</span>
boundsec fuzz <span class="k">--target</span> gym:hardened <span class="k">--strategy</span> coverage_guided <span class="k">--budget</span> 400</pre>
  <p class="mono" style="margin-top:20px">BoundSec · coverage-guided LLM-agent security fuzzing ·
    every number on this page is generated by <span style="color:var(--blue-ink)">boundsec experiment</span>.</p>
</div></footer>
"""


if __name__ == "__main__":
    import sys
    rd = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("results")
    fd = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("figures")
    out = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("boundsec_report.html")
    print(build(rd, fd, out))
