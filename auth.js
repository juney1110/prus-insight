/*!
 * PRUS Insight — Client-side Password Gate
 * NOTE: This is a soft gate (client-side check only).
 *       Real authentication should be implemented server-side.
 * Session-based (sessionStorage) — re-enter required per browser session.
 */
(function () {
  // SHA-256 hash of the access password
  const PASS_HASH = "05798b5867fa0524fc05cc67b0402d17dfc0afab384b4183b860567c14772013";
  const STORAGE_KEY = "prus_insight_auth_v1";

  // Already authenticated this session?
  try {
    if (sessionStorage.getItem(STORAGE_KEY) === "ok") return;
  } catch (e) { /* sessionStorage may be unavailable on file:// in some browsers */ }

  // Hide page immediately (before paint) to prevent flash of unauthorized content
  const htmlEl = document.documentElement;
  const prevVisibility = htmlEl.style.visibility;
  htmlEl.style.visibility = "hidden";

  async function sha256(text) {
    const buf = new TextEncoder().encode(text);
    const hashBuf = await crypto.subtle.digest("SHA-256", buf);
    return Array.from(new Uint8Array(hashBuf))
      .map(b => b.toString(16).padStart(2, "0")).join("");
  }

  function injectGate() {
    // Restore visibility so the gate itself can render
    htmlEl.style.visibility = prevVisibility || "visible";

    // CSS
    const style = document.createElement("style");
    style.setAttribute("data-pw-gate", "1");
    style.textContent = `
      .pw-gate-root{
        position:fixed;inset:0;z-index:99999;
        background:rgba(244,239,230,0.96);
        backdrop-filter:blur(18px) saturate(1.1);
        -webkit-backdrop-filter:blur(18px) saturate(1.1);
        display:flex;align-items:center;justify-content:center;
        font-family:"IBM Plex Sans KR", -apple-system, sans-serif;
        animation:pwFadeIn .3s ease;
        background-image:
          radial-gradient(ellipse at 12% -10%, rgba(184,72,43,0.10), transparent 45%),
          radial-gradient(ellipse at 88% 110%, rgba(42,79,75,0.10), transparent 55%);
      }
      @keyframes pwFadeIn{from{opacity:0}to{opacity:1}}
      @keyframes pwSlideIn{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}
      .pw-gate-root.exit{opacity:0;transition:opacity .35s ease}
      .pw-card{
        width:min(440px, 92vw);
        background:#FAF6EC;
        border:1px solid #D6CFBE;
        padding:3.2rem 2.8rem 2.6rem;
        position:relative;
        animation:pwSlideIn .45s cubic-bezier(.2,.7,.3,1) .05s both;
        box-shadow:0 30px 80px -40px rgba(28,27,23,0.25);
      }
      .pw-card::before{
        content:"";position:absolute;top:0;left:0;
        width:48px;height:3px;background:#B8482B;
      }
      .pw-brand{
        display:flex;align-items:baseline;gap:0.55rem;
        font-family:"Fraunces", "Noto Serif KR", Georgia, serif;
        font-weight:600;font-size:1.05rem;color:#1C1B17;letter-spacing:-0.01em;
        margin-bottom:0.4rem;
      }
      .pw-brand .pw-mark{
        display:inline-block;width:9px;height:9px;border-radius:50%;
        background:#B8482B;transform:translateY(1px);
      }
      .pw-brand small{
        font-family:"IBM Plex Sans KR", sans-serif;font-weight:400;font-size:0.7rem;
        color:#857F70;letter-spacing:0.1em;text-transform:uppercase;margin-left:0.3rem;
      }
      .pw-eyebrow{
        font-family:"JetBrains Mono", ui-monospace, monospace;font-size:0.7rem;
        color:#B8482B;letter-spacing:0.22em;text-transform:uppercase;
        margin:2rem 0 0.9rem;
      }
      .pw-title{
        font-family:"Fraunces", "Noto Serif KR", Georgia, serif;
        font-weight:300;font-size:2.1rem;line-height:1.05;letter-spacing:-0.025em;
        color:#1C1B17;
        font-variation-settings:"opsz" 96, "SOFT" 40;
      }
      .pw-title em{
        font-style:italic;color:#B8482B;font-weight:400;
        font-variation-settings:"opsz" 96, "SOFT" 100, "WONK" 1;
      }
      .pw-desc{
        font-family:"Fraunces", "Noto Serif KR", serif;font-style:italic;
        color:#3D3A33;font-size:0.95rem;line-height:1.5;margin-top:0.9rem;
      }
      .pw-form{margin-top:1.8rem}
      .pw-row{
        position:relative;display:flex;align-items:stretch;
        border:1px solid #BFB8A4;background:#fff;
        transition:border-color .2s;
      }
      .pw-row:focus-within{border-color:#B8482B;box-shadow:0 0 0 3px rgba(184,72,43,0.08)}
      .pw-input{
        flex:1;border:none;outline:none;background:transparent;
        padding:1rem 1.1rem;
        font-family:"JetBrains Mono", monospace;font-size:1rem;
        letter-spacing:0.3em;color:#1C1B17;
      }
      .pw-input::placeholder{color:#BFB8A4;letter-spacing:0.04em;font-family:"IBM Plex Sans KR"}
      .pw-btn{
        border:none;background:#1C1B17;color:#F4EFE6;
        padding:0 1.5rem;cursor:pointer;
        font-family:"JetBrains Mono", monospace;font-size:0.78rem;
        letter-spacing:0.14em;text-transform:uppercase;
        transition:background .2s;
      }
      .pw-btn:hover{background:#B8482B}
      .pw-btn:active{transform:translateY(1px)}
      .pw-err{
        min-height:1.3rem;margin-top:0.7rem;
        font-family:"JetBrains Mono", monospace;font-size:0.78rem;
        color:#B8482B;letter-spacing:0.04em;
        opacity:0;transition:opacity .2s;
      }
      .pw-err.show{opacity:1}
      .pw-foot{
        margin-top:2.2rem;padding-top:1.2rem;border-top:1px solid #D6CFBE;
        font-family:"JetBrains Mono", monospace;font-size:0.66rem;
        color:#857F70;letter-spacing:0.08em;line-height:1.5;
      }
      @keyframes pwShake{0%,100%{transform:translateX(0)}25%{transform:translateX(-6px)}75%{transform:translateX(6px)}}
      .pw-card.shake{animation:pwShake .35s ease}
    `;
    document.head.appendChild(style);

    // Modal HTML
    const root = document.createElement("div");
    root.className = "pw-gate-root";
    root.innerHTML = `
      <div class="pw-card">
        <div class="pw-brand">
          <span class="pw-mark"></span>
          PRUS Insight
          <small>B2B Insight Edition</small>
        </div>
        <div class="pw-eyebrow">RESTRICTED ACCESS</div>
        <div class="pw-title">접근 권한을<br/><em>확인합니다.</em></div>
        <p class="pw-desc">이 페이지는 PRUS Insight 구독자 전용입니다. 발급받은 접근 비밀번호를 입력하세요.</p>
        <form class="pw-form" autocomplete="off">
          <div class="pw-row">
            <input type="password" class="pw-input" placeholder="ACCESS CODE" autocomplete="new-password" inputmode="numeric" />
            <button type="submit" class="pw-btn">ENTER →</button>
          </div>
          <div class="pw-err" data-err></div>
        </form>
        <div class="pw-foot">
          © PRUS · Apartment Pre-Sale Intelligence · 비밀번호 분실 시 운영팀 문의
        </div>
      </div>
    `;
    document.body.appendChild(root);

    const card = root.querySelector(".pw-card");
    const input = root.querySelector(".pw-input");
    const err = root.querySelector("[data-err]");
    const form = root.querySelector(".pw-form");

    // Focus input
    setTimeout(() => input.focus(), 100);

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const val = input.value.trim();
      if (!val) return;
      let hash;
      try {
        hash = await sha256(val);
      } catch (err) {
        // SubtleCrypto may be unavailable on insecure contexts (file:// in some browsers)
        // Fallback: direct compare (not secure but functional)
        hash = null;
      }
      const ok = (hash && hash === PASS_HASH) || (!hash && val === "2633");
      if (ok) {
        try { sessionStorage.setItem(STORAGE_KEY, "ok"); } catch (e) {}
        root.classList.add("exit");
        setTimeout(() => root.remove(), 350);
      } else {
        err.textContent = "비밀번호가 일치하지 않습니다.";
        err.classList.add("show");
        card.classList.remove("shake");
        void card.offsetWidth;
        card.classList.add("shake");
        input.value = "";
        input.focus();
      }
    });
  }

  if (document.body) {
    injectGate();
  } else {
    document.addEventListener("DOMContentLoaded", injectGate);
  }
})();
