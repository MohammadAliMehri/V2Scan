(() => {
    "use strict";

    const $ = (id) => document.getElementById(id);
    const show = (id) => $(id).classList.remove("hidden");
    const hide = (id) => $(id).classList.add("hidden");

    let sessionId = null;
    let source = null;
    let filter = "all";
    let query = "";
    let results = [];
    let seen = new Set();
    let pending = [];
    let flushScheduled = false;
    let dist = { fast: 0, mid: 0, slow: 0 };
    let qrConfig = "";

    // ── Utilities ──────────────────────────────────────────────────────────────

    function toast(message, type = "") {
        const el = document.createElement("div");
        el.className = "toast" + (type ? " " + type : "");
        el.textContent = message;
        $("toasts").appendChild(el);
        setTimeout(() => el.remove(), 4000);
    }

    async function api(path, options = {}) {
        const init = { method: options.method || "GET" };
        if (options.body !== undefined) {
            init.method = "POST";
            init.headers = { "Content-Type": "application/json" };
            init.body = JSON.stringify(options.body);
        }
        const resp = await fetch(path, init);
        let data = {};
        try { data = await resp.json(); } catch { /* non-JSON error body */ }
        if (!resp.ok) throw new Error(data.error || `Request failed (${resp.status})`);
        return data;
    }

    async function copyText(text, okMessage) {
        try {
            await navigator.clipboard.writeText(text);
            toast(okMessage, "success");
        } catch {
            toast("Copy failed", "error");
        }
    }

    function setBusy(button, busy, label) {
        button.disabled = busy;
        if (label !== undefined) button.textContent = label;
    }

    const delayClass = (ms) => (ms < 500 ? "d-fast" : ms < 1500 ? "d-mid" : "d-slow");
    const fmtSeconds = (s) => (s <= 0 ? "-" : s < 60 ? `${Math.round(s)}s` : `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`);

    // ── Importing configs ──────────────────────────────────────────────────────

    document.querySelectorAll("#tabs .tab").forEach((tab) => {
        tab.addEventListener("click", () => {
            document.querySelectorAll("#tabs .tab").forEach((t) => t.classList.toggle("active", t === tab));
            ["paste", "github", "url", "file"].forEach((name) =>
                $("pane-" + name).classList.toggle("hidden", name !== tab.dataset.tab));
        });
    });

    function activeConfigs() {
        const order = { paste: "configInput", github: "githubConfigs", url: "urlConfigs", file: "configInput" };
        const active = document.querySelector("#tabs .tab.active").dataset.tab;
        const ids = [order[active], "configInput", "githubConfigs", "urlConfigs"];
        for (const id of ids) {
            const value = $(id).value.trim();
            if (value) return value;
        }
        return "";
    }

    function countProtocols(text) {
        const counts = {};
        let total = 0;
        for (const line of text.split("\n")) {
            const m = /^\s*(vless|vmess|trojan|ss|hysteria2|hy2):\/\//i.exec(line);
            if (!m) continue;
            const name = m[1].toLowerCase() === "hy2" ? "hysteria2" : m[1].toLowerCase();
            counts[name] = (counts[name] || 0) + 1;
            total++;
        }
        const box = $("protoPills");
        box.replaceChildren();
        if (!total) return;
        const add = (label) => {
            const pill = document.createElement("span");
            pill.className = "pill";
            pill.textContent = label;
            box.appendChild(pill);
        };
        add(`${total} configs`);
        Object.entries(counts).forEach(([name, n]) => add(`${name} ${n}`));
    }

    $("configInput").addEventListener("input", () => countProtocols($("configInput").value));

    $("githubBtn").addEventListener("click", async () => {
        const btn = $("githubBtn");
        setBusy(btn, true, "Fetching…");
        try {
            const d = await api("/api/fetch-github", { body: {} });
            $("githubConfigs").value = d.configs;
            show("githubConfigs");
            const list = $("sourceList");
            list.replaceChildren();
            const row = (text, count, err) => {
                const el = document.createElement("div");
                el.className = "source" + (err ? " err" : "");
                const a = document.createElement("span"), b = document.createElement("span");
                a.textContent = text; b.textContent = count;
                el.append(a, b);
                list.appendChild(el);
            };
            Object.entries(d.sources).sort((x, y) => y[1] - x[1]).forEach(([name, n]) => row(name, n, false));
            d.errors.forEach((e) => row(e, "failed", true));
            toast(`${d.count} unique configs (${d.total_fetched} raw, ${d.duplicates} duplicates)`, "success");
            countProtocols(d.configs);
        } catch (e) {
            toast(e.message, "error");
        } finally {
            setBusy(btn, false, "Fetch all sources");
        }
    });

    $("fetchUrlBtn").addEventListener("click", async () => {
        const url = $("subUrl").value.trim();
        if (!url) return toast("Enter a URL", "error");
        const btn = $("fetchUrlBtn");
        setBusy(btn, true, "Fetching…");
        try {
            const d = await api("/api/fetch-url", { body: { url } });
            $("urlConfigs").value = d.configs;
            countProtocols(d.configs);
            toast(`Fetched ${d.count} configs`, "success");
        } catch (e) {
            toast(e.message, "error");
        } finally {
            setBusy(btn, false, "Fetch");
        }
    });

    function loadFile(file) {
        if (!file) return;
        const reader = new FileReader();
        reader.onload = () => {
            $("configInput").value = reader.result;
            document.querySelector('[data-tab="paste"]').click();
            countProtocols(reader.result);
            toast(`Loaded ${file.name}`, "success");
        };
        reader.readAsText(file);
    }
    $("fileInput").addEventListener("change", (e) => loadFile(e.target.files[0]));
    const zone = $("dropZone");
    zone.addEventListener("dragover", (e) => { e.preventDefault(); zone.classList.add("drag"); });
    zone.addEventListener("dragleave", () => zone.classList.remove("drag"));
    zone.addEventListener("drop", (e) => {
        e.preventDefault();
        zone.classList.remove("drag");
        loadFile(e.dataTransfer.files[0]);
    });

    // ── Scan lifecycle ─────────────────────────────────────────────────────────

    function setRunning(running) {
        $("liveDot").classList.toggle("run", running);
        $("liveText").textContent = running ? "Scanning" : "Idle";
        $("cancelBtn").classList.toggle("hidden", !running);
        setBusy($("startBtn"), running, running ? "Scanning…" : "Start again");
    }

    function resetView() {
        results = [];
        seen = new Set();
        pending = [];
        dist = { fast: 0, mid: 0, slow: 0 };
        $("resultsBody").replaceChildren();
        updateDist();
        hide("exportCard");
    }

    $("startBtn").addEventListener("click", async () => {
        const configs = activeConfigs();
        if (!configs) return toast("No configs to scan", "error");
        const settings = {
            parallel: +$("parallel").value,
            timeout: +$("timeout").value,
            startup_wait: +$("startupWait").value,
            batch_size: +$("batchSize").value,
            singbox_path: $("singboxPath").value.trim() || "sing-box",
            probe_url: $("probeUrl").value.trim(),
        };
        setBusy($("startBtn"), true, "Starting…");
        try {
            const d = await api("/api/start", { body: { configs, settings } });
            resetView();
            sessionId = d.session_id;
            $("statTotal").textContent = d.total;
            show("dashboard");
            show("resultsCard");
            setRunning(true);
            listen();
        } catch (e) {
            toast(e.message, "error");
            setBusy($("startBtn"), false, "Start scan");
        }
    });

    $("cancelBtn").addEventListener("click", async () => {
        if (!sessionId) return;
        try { await api("/api/cancel", { body: { session_id: sessionId } }); } catch (e) { toast(e.message, "error"); }
    });

    function listen() {
        if (source) source.close();
        source = new EventSource("/api/events/" + sessionId);
        source.onmessage = (e) => {
            const d = JSON.parse(e.data);
            if (d.type === "started" || d.type === "stats") updateStats(d);
            else if (d.type === "result") queueResult(d);
            else if (d.type === "error") toast(d.message, "error");
            else if (d.type === "finished" || d.type === "done") onFinished(d);
        };
        // EventSource reconnects by itself; the server replays history and `seen` drops duplicates.
    }

    function onFinished(d) {
        if (source) { source.close(); source = null; }
        flush();
        updateStats(d);
        setRunning(false);
        show("exportCard");
        $("subHint").textContent = `Live subscription: ${location.origin}/sub/${sessionId}`;
        toast(d.cancelled ? "Scan cancelled" : "Scan complete", d.cancelled ? "" : "success");
    }

    function updateStats(d) {
        $("statDone").textContent = d.done || 0;
        $("statAlive").textContent = d.alive || 0;
        $("statDead").textContent = d.dead || 0;
        $("statSpeed").textContent = (d.speed || 0).toFixed(1);
        $("statAvg").textContent = (d.avg_delay || 0) + " ms";
        $("statMin").textContent = (d.min_delay || 0) + " ms";
        $("statEta").textContent = d.running ? fmtSeconds(d.eta || 0) : "-";
        const pct = d.progress || 0;
        $("progressBar").style.width = pct + "%";
        $("progressText").textContent = pct.toFixed(1) + "%";
        $("progressCount").textContent = `${d.done || 0} / ${d.total || 0}`;
    }

    function updateDist() {
        $("distFast").textContent = dist.fast;
        $("distMid").textContent = dist.mid;
        $("distSlow").textContent = dist.slow;
    }

    // ── Results table ──────────────────────────────────────────────────────────

    function queueResult(d) {
        if (seen.has(d.index)) return;
        seen.add(d.index);
        results.push(d);
        if (d.status === "alive") {
            dist[d.delay < 500 ? "fast" : d.delay < 1500 ? "mid" : "slow"]++;
        }
        pending.push(d);
        if (!flushScheduled) {
            flushScheduled = true;
            requestAnimationFrame(flush);
        }
    }

    function matches(d) {
        if (filter !== "all" && d.status !== filter) return false;
        if (!query) return true;
        return `${d.server} ${d.remark}`.toLowerCase().includes(query);
    }

    function cell(text, className) {
        const td = document.createElement("td");
        td.textContent = text;
        if (className) td.className = className;
        td.title = text;
        return td;
    }

    function buildRow(d) {
        const tr = document.createElement("tr");
        tr.appendChild(cell(d.index, "mono"));
        const proto = document.createElement("td");
        const badge = document.createElement("span");
        badge.className = "badge";
        badge.textContent = d.protocol;
        proto.appendChild(badge);
        tr.appendChild(proto);
        tr.appendChild(cell(d.server || "-", "mono"));
        tr.appendChild(cell(d.port || "-"));
        tr.appendChild(cell(d.remark || d.error || "-"));
        const alive = d.status === "alive";
        tr.appendChild(cell(alive ? "● Alive" : "○ Dead", alive ? "ok" : "ko"));
        tr.appendChild(cell(alive ? d.delay + " ms" : "-", alive ? delayClass(d.delay) : ""));
        const actions = document.createElement("td");
        if (alive && d.config) {
            const copy = document.createElement("button");
            copy.className = "btn icon";
            copy.textContent = "Copy";
            copy.addEventListener("click", () => copyText(d.config, "Config copied"));
            const qr = document.createElement("button");
            qr.className = "btn icon";
            qr.textContent = "QR";
            qr.style.marginLeft = "6px";
            qr.addEventListener("click", () => openQr(d));
            actions.append(copy, qr);
        }
        tr.appendChild(actions);
        return tr;
    }

    function flush() {
        flushScheduled = false;
        updateDist();
        const rows = pending.filter(matches).map(buildRow);
        pending = [];
        if (rows.length) $("resultsBody").append(...rows);
    }

    function rerender() {
        pending = [];
        $("resultsBody").replaceChildren(...results.filter(matches).map(buildRow));
    }

    $("filters").addEventListener("click", (e) => {
        const btn = e.target.closest("button");
        if (!btn) return;
        filter = btn.dataset.filter;
        document.querySelectorAll("#filters button").forEach((b) => b.classList.toggle("active", b === btn));
        rerender();
    });
    $("search").addEventListener("input", (e) => { query = e.target.value.trim().toLowerCase(); rerender(); });

    // ── Export ─────────────────────────────────────────────────────────────────

    $("exportTxt").addEventListener("click", () => sessionId && window.open(`/api/export/${sessionId}/txt`));
    $("exportJson").addEventListener("click", () => sessionId && window.open(`/api/export/${sessionId}/json`));
    $("copyAll").addEventListener("click", async () => {
        if (!sessionId) return;
        try {
            const d = await api(`/api/export/${sessionId}/clipboard`);
            await copyText(d.configs, `Copied ${d.count} configs`);
        } catch (e) { toast(e.message, "error"); }
    });
    $("copySub").addEventListener("click", () => sessionId && copyText(`${location.origin}/sub/${sessionId}`, "Subscription link copied"));

    // ── QR modal ───────────────────────────────────────────────────────────────

    function openQr(d) {
        qrConfig = d.config;
        const img = $("qrImg");
        img.classList.remove("hidden");
        hide("qrError");
        img.onerror = () => { img.classList.add("hidden"); $("qrError").textContent = "QR code unavailable for this config."; show("qrError"); };
        img.src = "/api/qr?data=" + encodeURIComponent(d.config);
        $("qrCaption").textContent = `${d.protocol} · ${d.server}:${d.port} · ${d.delay} ms`;
        show("qrModal");
    }
    function closeQr() { hide("qrModal"); $("qrImg").removeAttribute("src"); }
    $("qrClose").addEventListener("click", closeQr);
    $("qrModal").addEventListener("click", (e) => { if (e.target === $("qrModal")) closeQr(); });
    document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeQr(); });
    $("qrCopy").addEventListener("click", () => copyText(qrConfig, "Config copied"));
})();
