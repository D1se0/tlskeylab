import { useEffect, useRef, useState } from 'react'

/* ---------- utilidades de animación ---------- */

function useReveal() {
  useEffect(() => {
    const obs = new IntersectionObserver(
      (es) => es.forEach((e) => e.isIntersecting && e.target.classList.add('visible')),
      { threshold: 0.15 }
    )
    document.querySelectorAll('.reveal').forEach((el) => obs.observe(el))
    return () => obs.disconnect()
  }, [])
}

function Particles() {
  const ref = useRef(null)
  useEffect(() => {
    const c = ref.current, ctx = c.getContext('2d')
    let w, h, raf
    const P = Array.from({ length: 70 }, () => ({
      x: Math.random(), y: Math.random(),
      vx: (Math.random() - 0.5) * 0.0006, vy: (Math.random() - 0.5) * 0.0006,
      r: Math.random() * 1.6 + 0.4,
    }))
    const resize = () => { w = c.width = c.offsetWidth; h = c.height = c.offsetHeight }
    resize(); window.addEventListener('resize', resize)
    const loop = () => {
      ctx.clearRect(0, 0, w, h)
      P.forEach((p) => {
        p.x = (p.x + p.vx + 1) % 1; p.y = (p.y + p.vy + 1) % 1
        const x = p.x * w, y = p.y * h
        ctx.beginPath(); ctx.arc(x, y, p.r, 0, 7)
        ctx.fillStyle = 'rgba(0,229,255,0.55)'; ctx.fill()
      })
      // neuronas: líneas entre partículas próximas
      for (let i = 0; i < P.length; i++) for (let j = i + 1; j < P.length; j++) {
        const dx = (P[i].x - P[j].x) * w, dy = (P[i].y - P[j].y) * h
        const d = Math.hypot(dx, dy)
        if (d < 110) {
          ctx.strokeStyle = `rgba(124,77,255,${0.35 * (1 - d / 110)})`
          ctx.beginPath(); ctx.moveTo(P[i].x * w, P[i].y * h); ctx.lineTo(P[j].x * w, P[j].y * h); ctx.stroke()
        }
      }
      raf = requestAnimationFrame(loop)
    }
    loop()
    return () => { cancelAnimationFrame(raf); window.removeEventListener('resize', resize) }
  }, [])
  return <canvas ref={ref} className="particles" aria-hidden="true" />
}

const LINES = [
  'C:\\> tlskeylab.exe setup',
  'Variable SSLKEYLOGFILE fijada (HKCU\\Environment)... OK',
  'Recurso SMB \\\\h4cknet\\tlskeys activo (solo lectura)... OK',
  'C:\\> tlskeylab.exe launch chrome',
  'Chrome lanzado con SSLKEYLOGFILE inyectada... OK',
  'CLIENT_HANDSHAKE_TRAFFIC_SECRET 3e5d3293ba6af... 5c82d8...',
  'C:\\> tlskeylab.exe capture',
  'Capturando en interfaz 4 hasta Ctrl+C...',
  'C:\\Users\\diseo\\tlskeylab\\capture_20261012.pcapng ✔',
]

function Terminal() {
  const [shown, setShown] = useState([])
  const [cur, setCur] = useState('')
  useEffect(() => {
    let li = 0, ci = 0, t
    const tick = () => {
      if (li >= LINES.length) { t = setTimeout(() => { setShown([]); setCur(''); li = 0; ci = 0; tick() }, 4000); return }
      const line = LINES[li]
      if (ci <= line.length) { setCur(line.slice(0, ci)); ci++; t = setTimeout(tick, line.startsWith('C:\\>') ? 55 : 14) }
      else { setShown((s) => [...s.slice(-7), line]); setCur(''); ci = 0; li++; t = setTimeout(tick, li === LINES.length ? 200 : 420) }
    }
    tick()
    return () => clearTimeout(t)
  }, [])
  const isCmd = (l) => l && l.startsWith('C:\\>')
  return (
    <div className="term">
      <div className="term-bar"><span /><span /><span /><em>cmd — tlskeylab</em></div>
      <div className="term-body">
        {shown.map((l, i) => <div key={i} className={isCmd(l) ? 'ln cmd' : 'ln ok'}>{l}</div>)}
        <div className={'ln ' + (isCmd(cur) ? 'cmd' : cur ? 'ok' : '')}>{cur}<span className="caret" /></div>
      </div>
    </div>
  )
}

/* ---------- datos ---------- */

const TOOLS = [
  { icon: '⚙️', name: 'tlskeylab.exe', tag: 'Windows · Go · ~2 MB',
    desc: 'Automatiza todo el lado de la víctima: crea el keylog, fija SSLKEYLOGFILE en el registro, comparte las claves por SMB, permite el puerto en el firewall y auto-instala Wireshark vía winget si falta dumpcap.',
    cmds: ['setup', 'status', 'launch chrome', 'capture [s] [-i N]', 'uninstall [--purge]'] },
  { icon: '🖥️', name: 'tlsviewer.py', tag: 'Linux/Win/macOS · Python',
    desc: 'En la máquina atacante: detecta el keylog y el pcapng de una carpeta, escribe el perfil TLSKeyLab de Wireshark con tls.keylog_file configurado y abre Wireshark ya descifrando.',
    cmds: ['python3 tlsviewer.py', '--keylog R --pcap R', '--dir DIR --list'] },
  { icon: '🧪', name: 'e2e_test.ps1', tag: 'PowerShell',
    desc: 'Prueba end-to-end real: arranca dumpcap, navega con Chrome headless y verifica con tshark que el pcap se descifra con el keylog.',
    cmds: ['powershell -File e2e_test.ps1'] },
]

const FLOW = [
  { n: '01', t: 'setup', d: 'SSLKEYLOGFILE → HKCU\\Environment + keylog vacío + share SMB + regla firewall' },
  { n: '02', t: 'launch chrome', d: 'El navegador nace con la variable inyectada: escribe sus secretos TLS al keylog' },
  { n: '03', t: 'capture', d: 'dumpcap captura el tráfico y lo deja en capture_<fecha>.pcapng junto al keylog' },
  { n: '04', t: 'transport', d: 'El atacante copia sslkeys.log + pcapng por SMB (\\\\víctima\\tlskeys)' },
  { n: '05', t: 'tlsviewer.py', d: 'Wireshark se abre con el perfil TLSKeyLab: HTTP/2 en texto claro al instante' },
]

const THEORY = [
  { q: '¿Por qué no se ve el HTTPS en Wireshark?', a: 'Porque TLS cifra extremo a extremo con una clave simétrica acordada en el handshake. Wireshark solo ve bytes cifrados: URLs, cabeceras y cuerpos son indistinguibles del ruido.' },
  { q: '¿De dónde salen entonces las claves?', a: 'De la memoria del propio navegador. La convención SSLKEYLOGFILE (heredada de NSS/Firefox y adoptada por Chrome y Edge) hace que el navegador escriba en un fichero los secretos de cada handshake SI esa variable está definida al arrancar.' },
  { q: '¿Cómo empareja Wireshark clave y paquete?', a: 'Cada línea del keylog lleva el Random del ClientHello (32 bytes que viajan en claro en cada handshake). Wireshark lo lee del pcap, lo busca en el keylog y deriva las claves de esa sesión aplicando la misma HKDF.' },
  { q: '¿Puede un atacante en la red hacerlo sin tocar la víctima?', a: 'No. El secreto nace de Diffie-Hellman efímero: capturar los paquetes no basta para calcularlo (logaritmo discreto). Y la variable de entorno solo se lee al nacer el proceso. Por esto es análisis consentido, no intercepción.' },
  { q: '¿Qué NO puede hacer esta técnica?', a: 'No es retroactiva (sesiones previas al launch quedan fuera), no cubre apps que no escriben keylog (curl, PowerShell, Schannel), y no afecta a otros usuarios del sistema. Cada pieza es visible y reversible con uninstall.' },
]

/* ---------- secciones ---------- */

function Hero() {
  return (
    <header className="hero">
      <Particles />
      <div className="hero-inner">
        <div className="hero-left reveal visible">
          <div className="badge">🦈 LAB LOCAL · SOLO TRÁFICO PROPIO · 100% REVERSIBLE</div>
          <h1><span className="grad">tlskeylab</span></h1>
          <p className="tag">Descifra tu propio HTTPS en Wireshark con la técnica estándar <b>SSLKEYLOGFILE</b> — automatizado, documentado y con desinstalación limpia.</p>
          <div className="cta">
            <a href="#tools" className="btn primary">Ver herramientas</a>
            <a href="#flow" className="btn ghost">Cómo funciona</a>
          </div>
        </div>
        <div className="hero-right reveal visible"><Terminal /></div>
      </div>
      <div className="wave"><svg viewBox="0 0 1440 90" preserveAspectRatio="none"><path d="M0,60 C240,100 480,10 720,50 C960,90 1200,20 1440,60 L1440,90 L0,90 Z" /></svg></div>
    </header>
  )
}

function Tools() {
  return (
    <section id="tools" className="section">
      <h2 className="reveal">Las <b className="grad">herramientas</b></h2>
      <p className="lead reveal">Suite 100% didáctica para tu laboratorio local (equipos propios, IPs privadas).</p>
      <div className="grid3">
        {TOOLS.map((t, i) => (
          <article className="card reveal" key={i} style={{ transitionDelay: `${i * 90}ms` }}>
            <span className="card-icon">{t.icon}</span>
            <h3>{t.name}</h3>
            <span className="pill">{t.tag}</span>
            <p>{t.desc}</p>
            <div className="cmds">{t.cmds.map((c) => <code key={c}>{c}</code>)}</div>
          </article>
        ))}
      </div>
    </section>
  )
}

function Flow() {
  return (
    <section id="flow" className="section alt">
      <h2 className="reveal">El flujo en <b className="grad">5 pasos</b></h2>
      <div className="flow">
        {FLOW.map((s, i) => (
          <div className="step reveal" key={s.n} style={{ transitionDelay: `${i * 120}ms` }}>
            <div className="bubble"><span>{s.n}</span><label>{s.t}</label></div>
            <p>{s.d}</p>
            {i < FLOW.length - 1 && <div className="arrow" />}
          </div>
        ))}
      </div>
      <div className="keyline reveal">
        <pre>CLIENT_HANDSHAKE_TRAFFIC_SECRET  3e5d3293ba6af989...  5c82d8575aae338c...</pre>
        <small>↑ una línea = una clave de sesión TLS: etiqueta + Random del ClientHello (va en claro) + el secreto</small>
      </div>
    </section>
  )
}

function Theory() {
  const [open, setOpen] = useState(0)
  return (
    <section id="theory" className="section">
      <h2 className="reveal">Teoría: <b className="grad">qué pasa por dentro</b></h2>
      <p className="lead reveal">Handshake TLS, secretos y por qué esto es análisis y no intercepción.</p>
      <div className="acc reveal">
        {THEORY.map((t, i) => (
          <div className={'acc-item' + (open === i ? ' open' : '')} key={i}>
            <button onClick={() => setOpen(open === i ? -1 : i)}>
              <span>{t.q}</span><em>▾</em>
            </button>
            <div className="acc-body"><p>{t.a}</p></div>
          </div>
        ))}
      </div>
    </section>
  )
}

function Ethics() {
  return (
    <section className="section ethics reveal">
      <h3>⚖️ Marco ético</h3>
      <p>tlskeylab habilita el keylog TLS <b>solo en la máquina donde lo ejecutas</b>, con cambios visibles en el log y reversibles con <code>uninstall</code>. No captura de terceros, no MITM, no persistencia oculta. Pensado para laboratorios docentes con equipos propios.</p>
    </section>
  )
}

function Footer() {
  return (
    <footer className="footer">
      <span>🦈 tlskeylab — hecho como material de laboratorio · <a href="https://github.com/D1se0">github.com/D1se0</a></span>
    </footer>
  )
}

export default function App() {
  useReveal()
  return (
    <>
      <nav className="nav">
        <a href="#top" className="logo">🦈 tlskeylab</a>
        <div>
          <a href="#tools">Herramientas</a>
          <a href="#flow">Flujo</a>
          <a href="#theory">Teoría</a>
          <a className="nav-gh" href="https://github.com/D1se0" target="_blank" rel="noreferrer">GitHub ↗</a>
        </div>
      </nav>
      <div id="top"><Hero /></div>
      <Tools />
      <Flow />
      <Theory />
      <Ethics />
      <Footer />
    </>
  )
}
