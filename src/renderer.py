import html


def render_cert_card(result: dict) -> str:
    host = html.escape(result.get("hostname", "unknown"))

    if not result.get("ok"):
        err = html.escape(result.get("error", "Unknown inspection error"))
        return f"""
        <article class="cert-card">
          <div class="card-header">
            <strong>{host}</strong>
            <span class="pill pill-ERROR">HANDSHAKE ERROR</span>
          </div>
          <p style="font-size: 0.84rem; color: #991b1b;">{err}</p>
        </article>
        """

    health = html.escape(result["health"])
    issuer = html.escape(result["issuer_org"])
    tls_ver = html.escape(result["tls_version"])
    cipher = html.escape(result["cipher"])
    valid_until = html.escape(result["valid_until"])
    days = result["days_remaining"]
    sans_html = "".join(
        f'<span class="san-tag">{html.escape(san)}</span>' for san in result.get("sans", [])
    )

    return f"""
    <article class="cert-card">
      <div class="card-header">
        <strong>{host}</strong>
        <span class="pill pill-{health}">{health} &bull; {days}d left</span>
      </div>
      <div class="meta-row"><span>Issuer CA</span><strong>{issuer}</strong></div>
      <div class="meta-row"><span>Protocol / Cipher</span><strong>{tls_ver} ({result['key_bits']}-bit)</strong></div>
      <div class="meta-row"><span>Cipher Suite</span><strong>{cipher}</strong></div>
      <div class="meta-row"><span>Expires On</span><strong>{valid_until}</strong></div>
      <div class="san-list">{sans_html}</div>
    </article>
    """


def render_dashboard_page(watchlist_results: list[dict], instant_result: dict | None = None) -> str:
    instant_section = ""
    if instant_result:
        instant_section = f"""
        <section>
          <h2 style="font-size: 0.95rem; margin-bottom: 0.75rem; color: #0f3d3e;">
            Latest On-Demand Probe Result
          </h2>
          {render_cert_card(instant_result)}
        </section>
        """

    cards_html = "".join(render_cert_card(item) for item in watchlist_results)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>CertSentinel // Python TLS &amp; SSL Web Auditor</title>
  <link rel="stylesheet" href="/static/styles.css" />
</head>
<body>
  <header class="topbar">
    <div class="brand">
      <span class="brand-badge">TLS 1.3</span>
      <div>
        <h1 style="font-size: 1.05rem;">CertSentinel // SSL Certificate Web Auditor</h1>
        <p style="font-size: 0.75rem; opacity: 0.8;">Python Standard Library HTTP &amp; X.509 Inspector</p>
      </div>
    </div>
    <span style="font-size: 0.78rem; opacity: 0.85;">JSON API: <code>/api/inspect?domain=example.com</code></span>
  </header>

  <main class="container">
    <section class="probe-panel">
      <h2 style="font-size: 1rem;">Inspect Live Domain Certificate</h2>
      <p style="font-size: 0.82rem; color: #526d6e;">
        Enter any HTTPS hostname to inspect its X.509 certificate chain, SAN entries, and expiration window.
      </p>
      <form class="probe-form" method="POST" action="/inspect">
        <input type="text" name="domain" placeholder="e.g. stripe.com or wikipedia.org" required />
        <label style="display:flex; align-items:center; gap:0.4rem; font-size:0.82rem; color:#102a2b;">
          <input type="checkbox" name="save_watchlist" value="1" checked />
          Pin to Watchlist
        </label>
        <button type="submit">Run TLS Handshake</button>
      </form>
    </section>

    {instant_section}

    <section>
      <h2 style="font-size: 0.95rem; margin-bottom: 0.75rem; color: #0f3d3e;">
        Pinned Domain Watchlist ({len(watchlist_results)} Monitored)
      </h2>
      <div class="grid-cards">
        {cards_html}
      </div>
    </section>
  </main>
</body>
</html>"""