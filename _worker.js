// EMBY-PROXY-ULTIMATE V16.1
// [V16.1] UI Branding update, Multi-language (En/Zh-Hans/Zh-Hant), GitHub Footer
// 融合版本：V14 的稳定性 + V15 的缓存架构 + V13 的兼容性
// 核心特性：L1 内存级缓存 | 零延迟 | 稳健 JWT | 极致资源优化

// ============================================================================
// 0. GLOBAL CONFIG & STATE (L1 MEMORY CACHE)
// ============================================================================
// 利用 Worker 实例在内存中存活的特性，实现配置 "0 Latency" 读取
const GLOBALS = {
    // [Tier 1 Cache] Key: nodeName, Value: { data: object, exp: number }
    NodeCache: new Map(),

    // 预编译正则，提升运行时性能
    Regex: {
        Static: /\.(?:jpg|jpeg|gif|png|svg|ico|webp|js|css|woff2?|ttf|otf|map|webmanifest|json)$/i,
        Streaming: /\.(?:mp4|m4v|m4s|m4a|ogv|webm|mkv|mov|avi|wmv|flv|ts|m3u8|mpd)$/i
    },

    // 纯数学计算判断北京时间 (UTC+8) 是否为白天 (6-18点)
    // 性能优于 Intl API 约 100 倍
    isDaytimeCN: () => {
        const h = (new Date().getUTCHours() + 8) % 24;
        return h >= 6 && h < 18;
    }
};

const Config = {
    Defaults: {
        JwtExpiry: 60 * 60 * 24 * 7, // 7天
        LoginLockDuration: 900,      // 锁定 15 分钟
        MaxLoginAttempts: 5,         // 最大尝试 5 次
        CacheTTL: 60000              // L1 内存缓存一致性刷新时间 (60秒)
    }
};

// ============================================================================
// 1. AUTH MODULE (Standard & Secure)
// ============================================================================
// 采用 V14 的标准实现，避免 V15 激进简写可能带来的编码兼容性问题
const Auth = {
    async handleLogin(request, env) {
        const ip = request.headers.get("cf-connecting-ip") || "unknown";
        try {
            const formData = await request.formData();
            const password = (formData.get("password") || "").trim();
            const secret = env.JWT_SECRET || env.ADMIN_PASS;

            // 1. 成功登录
            if (password === env.ADMIN_PASS) {
                // 异步清除失败记录，不阻塞主线程
                if (env.ENI_KV) env.ENI_KV.delete(`fail:${ip}`).catch(() => { });
                const jwt = await this.generateJwt(secret, Config.Defaults.JwtExpiry);
                return new Response("Login Success", {
                    status: 302,
                    headers: {
                        "Location": "/admin",
                        "Set-Cookie": `auth_token=${jwt}; Path=/; Max-Age=${Config.Defaults.JwtExpiry}; HttpOnly; Secure; SameSite=Strict`
                    }
                });
            }

            // 2. 失败计数
            let count = 0;
            if (env.ENI_KV) {
                const failKey = `fail:${ip}`;
                const prev = await env.ENI_KV.get(failKey);
                count = prev ? parseInt(prev) + 1 : 1;
                if (count <= Config.Defaults.MaxLoginAttempts) {
                    env.ENI_KV.put(failKey, count.toString(), { expirationTtl: Config.Defaults.LoginLockDuration }).catch(() => { });
                }
            }

            if (count >= Config.Defaults.MaxLoginAttempts) return UI.renderLockedPage(ip);
            return UI.renderLoginPage(`密码错误 (剩余次数: ${Config.Defaults.MaxLoginAttempts - count})`);
        } catch (e) { return UI.renderLoginPage("请求无效"); }
    },

    async verifyRequest(request, env) {
        const cookie = request.headers.get("Cookie");
        if (!cookie) return false;
        const match = cookie.match(/auth_token=([^;]+)/);
        const token = match ? match[1] : null;
        if (!token) return false;
        return await this.verifyJwt(token, env.JWT_SECRET || env.ADMIN_PASS);
    },

    async generateJwt(secret, expiresIn) {
        const header = { alg: "HS256", typ: "JWT" };
        const payload = { sub: "admin", exp: Math.floor(Date.now() / 1000) + expiresIn };
        const encHeader = this.base64UrlEncode(JSON.stringify(header));
        const encPayload = this.base64UrlEncode(JSON.stringify(payload));
        const signature = await this.sign(secret, `${encHeader}.${encPayload}`);
        return `${encHeader}.${encPayload}.${signature}`;
    },

    async verifyJwt(token, secret) {
        const parts = token.split('.');
        if (parts.length !== 3) return false;
        const [h, p, s] = parts;
        const expected = await this.sign(secret, `${h}.${p}`);
        if (s !== expected) return false;
        try {
            const payload = JSON.parse(this.base64UrlDecode(p));
            return payload.exp > Math.floor(Date.now() / 1000);
        } catch (e) { return false; }
    },

    // 标准 Base64URL 编解码，比 V15 的 replace 更加稳健
    base64UrlEncode(str) { return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); },
    base64UrlDecode(str) { return atob(str.replace(/-/g, '+').replace(/_/g, '/')); },

    async sign(secret, data) {
        const enc = new TextEncoder();
        const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
        const signature = await crypto.subtle.sign("HMAC", key, enc.encode(data));
        return this.base64UrlEncode(String.fromCharCode(...new Uint8Array(signature)));
    }
};

// ============================================================================
// 2. DATABASE MODULE (Three-Tier Caching Architecture)
// ============================================================================
const Database = {
    PREFIX: "node:",

    async getNode(nodeName, env, ctx) {
        if (!env.ENI_KV) return null;

        // [Tier 1] Memory Cache (Microsecond Latency)
        // 直接从内存读取，不消耗 KV 读写额度
        const now = Date.now();
        const mem = GLOBALS.NodeCache.get(nodeName);
        if (mem && mem.exp > now) {
            return mem.data;
        }

        const cache = caches.default;
        const cacheUrl = new URL(`https://internal-config-cache/node/${nodeName}`);

        // [Tier 2] Cache API (Low Millisecond Latency)
        // 这里的 Cache API 是 Cloudflare 的区域缓存
        let response = await cache.match(cacheUrl);
        if (response) {
            const data = await response.json();
            // 回填 Tier 1
            GLOBALS.NodeCache.set(nodeName, { data, exp: now + Config.Defaults.CacheTTL });
            return data;
        }

        // [Tier 3] KV Store (Slowest ~50ms+, Costs $$$)
        // 只有前两层都击穿时才读 KV
        try {
            const nodeData = await env.ENI_KV.get(`${this.PREFIX}${nodeName}`, { type: "json" });
            if (nodeData) {
                // 回填 Tier 2 (异步写入，不阻塞响应)
                const jsonStr = JSON.stringify(nodeData);
                const cacheResp = new Response(jsonStr, {
                    headers: { "Cache-Control": "public, max-age=60, stale-while-revalidate=600" }
                });
                ctx.waitUntil(cache.put(cacheUrl, cacheResp));

                // 回填 Tier 1
                GLOBALS.NodeCache.set(nodeName, { data: nodeData, exp: now + Config.Defaults.CacheTTL });
                return nodeData;
            }
        } catch (err) { console.error(`KV Error: ${err}`); }
        return null;
    },

    async handleApi(request, env) {
        if (!env.ENI_KV) return new Response(JSON.stringify({ error: "KV Not Bound" }), { status: 500 });
        const data = await request.json();
        const cache = caches.default;

        // 缓存失效策略：修改时清除 L1 和 L2
        const invalidate = async (name) => {
            GLOBALS.NodeCache.delete(name);
            await cache.delete(`https://internal-config-cache/node/${name}`);
        };

        switch (data.action) {
            case "save":
            case "import":
                const nodesToSave = data.action === "save" ? [data] : data.nodes;
                for (const n of nodesToSave) {
                    if (n.name && n.target) {
                        const val = { secret: n.secret || n.path || "", target: n.target };
                        await env.ENI_KV.put(`${this.PREFIX}${n.name}`, JSON.stringify(val));
                        await invalidate(n.name);
                    }
                }
                return new Response(JSON.stringify({ success: true }));

            case "delete":
                if (data.name) {
                    await env.ENI_KV.delete(`${this.PREFIX}${data.name}`);
                    await invalidate(data.name);
                }
                return new Response(JSON.stringify({ success: true }));

            case "list":
                // 列表操作必须读 KV，但详情可尝试读内存优化速度
                const list = await env.ENI_KV.list({ prefix: this.PREFIX });
                const nodesList = await Promise.all(list.keys.map(async (key) => {
                    const name = key.name.replace(this.PREFIX, "");
                    // 尝试 Tier 1 命中
                    let val = GLOBALS.NodeCache.get(name)?.data;
                    if (!val) val = await env.ENI_KV.get(key.name, { type: "json" });
                    return val ? { name, ...val } : null;
                }));
                return new Response(JSON.stringify({ nodes: nodesList.filter(n => n) }));

            default: return new Response("Invalid Action", { status: 400 });
        }
    }
};

// ============================================================================
// 3. PROXY MODULE (Performance Optimized)
// ============================================================================
const Proxy = {
    async handle(request, node, path, name, key) {
        const targetBase = new URL(node.target);
        const finalUrl = new URL(path, targetBase);
        finalUrl.search = new URL(request.url).search;

        // WebSocket 快速通道
        if (request.headers.get("Upgrade") === "websocket") {
            return this.handleWebSocket(finalUrl, request);
        }

        if (request.method === "OPTIONS") return this.renderCors();

        const isStreaming = GLOBALS.Regex.Streaming.test(path);

        // 优化 Header 处理：Lazy Clone
        const newHeaders = new Headers(request.headers);
        newHeaders.set("Host", targetBase.host);
        newHeaders.set("X-Real-IP", request.headers.get("cf-connecting-ip"));
        newHeaders.set("X-Forwarded-For", request.headers.get("cf-connecting-ip"));

        // 删除 Cloudflare 特有 Header 防止上游误判
        ["cf-connecting-ip", "cf-ipcountry", "cf-ray", "cf-visitor", "cf-worker"].forEach(h => newHeaders.delete(h));

        if (isStreaming) newHeaders.delete("Referer");

        // 缓存策略：流媒体不缓存，静态资源强缓存
        const cf = isStreaming
            ? { cacheEverything: false, cacheTtl: 0 }
            : { cacheEverything: true, cacheTtlByStatus: { "200-299": 86400 } };

        try {
            const response = await fetch(finalUrl.toString(), {
                method: request.method,
                headers: newHeaders,
                body: request.body,
                redirect: "manual",
                cf
            });

            // 修正响应 Header
            const modifiedHeaders = new Headers(response.headers);
            modifiedHeaders.set("Access-Control-Allow-Origin", "*");
            if (isStreaming) modifiedHeaders.set("Cache-Control", "no-store");

            this.rewriteLocation(modifiedHeaders, response.status, name, key, targetBase);

            return new Response(response.body, {
                status: response.status,
                statusText: response.statusText,
                headers: modifiedHeaders
            });

        } catch (err) {
            return UI.renderSmartError(request, err.message, name);
        }
    },

    handleWebSocket(url, request) {
        try {
            const protocols = request.headers.get("Sec-WebSocket-Protocol") || "emby-websocket";
            const wsTarget = new URL(url);
            wsTarget.protocol = wsTarget.protocol === 'https:' ? 'wss:' : 'ws:';

            const { 0: client, 1: server } = new WebSocketPair();
            const ws = new WebSocket(wsTarget.toString(), protocols);

            server.accept();

            // 采用 V14 的事件监听方式，比 V15 的极简写法更安全 (捕获 try-catch)
            ws.addEventListener('message', e => { try { server.send(e.data) } catch { } });
            server.addEventListener('message', e => { try { ws.send(e.data) } catch { } });

            // 统一关闭处理
            const close = () => {
                try { server.close() } catch { }
                try { ws.close() } catch { }
            };
            ws.addEventListener('close', close);
            server.addEventListener('close', close);
            ws.addEventListener('error', close);
            server.addEventListener('error', close);

            return new Response(null, {
                status: 101,
                webSocket: client,
                headers: { "Sec-WebSocket-Protocol": protocols }
            });
        } catch (e) {
            return new Response("WS Error", { status: 502 });
        }
    },

    rewriteLocation(headers, status, name, key, targetBase) {
        if (status < 300 || status >= 400) return;
        const location = headers.get("Location");
        if (!location) return;

        const prefix = key ? `/${name}/${key}` : `/${name}`;
        if (location.startsWith("/")) {
            headers.set("Location", `${prefix}${location}`);
        } else {
            try {
                const locUrl = new URL(location);
                if (locUrl.host === targetBase.host) {
                    headers.set("Location", `${prefix}${locUrl.pathname}${locUrl.search}`);
                }
            } catch (e) { }
        }
    },

    renderCors() {
        return new Response(null, {
            headers: {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
                "Access-Control-Allow-Headers": "*"
            }
        });
    }
};

// ============================================================================
// 4. UI MODULE (Compact & Aesthetic)
// ============================================================================
const UI = {
    getHead(title) {
        const isLight = GLOBALS.isDaytimeCN();
        // 极致压缩的 CSS，但功能完整，支持日夜切换
        return `<!DOCTYPE html><html class="${isLight ? 'light' : ''}"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title><style>:root{--bg:#111;--p:#222;--b:#333;--t:#eee;--ts:#888;--a:#22c55e;--ah:#16a34a;--e:#ef4444}html.light{--bg:#f5f5f5;--p:#fff;--b:#e0e0e0;--t:#333;--ts:#666;--a:#16a34a;--ah:#15803d}body{background:var(--bg);color:var(--t);font-family:system-ui,-apple-system,sans-serif;margin:0;display:flex;flex-direction:column;min-height:100vh}input,button{transition:all .3s}.panel{background:var(--p);border:1px solid var(--b);border-radius:8px}.btn{cursor:pointer;border:none;border-radius:4px;font-weight:700}.btn-p{background:var(--a);color:#fff}.btn-p:hover{background:var(--ah)}.lang-btn{cursor:pointer;padding:5px;border-radius:50%;display:flex;align-items:center;justify-content:center;color:var(--t)}.lang-btn:hover{background:var(--b)}.gh-icon{color:var(--ts);transition:color .3s}.gh-icon:hover{color:var(--t)}</style></head>`;
    },

    escapeHtml(unsafe) {
        if (!unsafe) return "";
        return unsafe.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
    },

    renderSmartError(request, msg, nodeName) {
        if (request.headers.get("Accept")?.includes("text/html")) {
            return new Response(`${this.getHead("Error")}<body><div style="display:flex;justify-content:center;align-items:center;height:100vh"><div class="panel" style="padding:40px;text-align:center"><h2>连接失败</h2><p>节点: <strong>${this.escapeHtml(nodeName)}</strong></p><p style="color:var(--e);font-family:monospace;background:var(--bg);padding:10px;border-radius:4px">${this.escapeHtml(msg)}</p><button onclick="location.reload()" class="btn btn-p" style="padding:10px 24px">重试</button></div></div></body></html>`, { status: 502, headers: { "Content-Type": "text/html;charset=utf-8" } });
        }
        return new Response(JSON.stringify({ error: msg, node: nodeName }), { status: 502, headers: { "Content-Type": "application/json" } });
    },

    renderLoginPage(error = "") {
        return new Response(`${this.getHead("Login")}<body><div style="display:flex;justify-content:center;align-items:center;height:100vh"><div class="panel" style="padding:30px;width:300px"><h3>Emby Proxy Admin</h3><form method="POST"><input type="password" name="password" placeholder="Password" style="width:100%;padding:10px;margin-bottom:15px;box-sizing:border-box;background:var(--bg);border:1px solid var(--b);color:var(--t);border-radius:4px" required>${error ? `<div style="color:var(--e);font-size:12px;margin-bottom:10px;text-align:center">${this.escapeHtml(error)}</div>` : ''}<button class="btn btn-p" style="width:100%;padding:10px">登 录</button></form></div></div></body></html>`, { headers: { "Content-Type": "text/html" } });
    },

    renderLockedPage(ip) {
        return new Response(`${this.getHead("Locked")}<body><div style="display:flex;justify-content:center;align-items:center;height:100vh;text-align:center"><div><h1 style="color:var(--e)">IP 已锁定</h1><p>IP: ${this.escapeHtml(ip)}</p><p>尝试次数过多，请 15 分钟后再试。</p></div></div></body></html>`, { status: 429, headers: { "Content-Type": "text/html" } });
    },

    // [V16.1] Updated to include Language Logic and Footer
    renderAdminUI() {
        const html = `
${this.getHead("Admin")}
<body style="padding:20px;max-width:1000px;margin:0 auto;width:100%;box-sizing:border-box">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;padding-bottom:15px;border-bottom:1px solid var(--b)">
        <h2 style="margin:0">Emby Proxy <span style="font-size:12px;color:var(--ts);font-weight:normal">V16.1</span></h2>
        <div style="display:flex;align-items:center;gap:15px">
             <div id="clk" style="font-family:monospace;font-size:12px;color:var(--ts)"></div>
             <div class="lang-btn" onclick="App.toggleLang()" title="Switch Language">
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>
             </div>
        </div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 2fr;gap:20px;flex:1" class="grid-box">
        <style>@media(max-width:700px){.grid-box{grid-template-columns:1fr !important}}</style>
        <div class="panel" style="padding:20px;height:fit-content">
            <h3 style="margin-top:0" id="t-new">New Node</h3>
            <input id="inName" placeholder="Name (e.g. HK)" style="width:100%;padding:8px;margin:5px 0 15px;background:var(--bg);border:1px solid var(--b);color:var(--t);border-radius:4px;box-sizing:border-box">
            <input id="inTarget" placeholder="Target (http://1.2.3.4:8096)" style="width:100%;padding:8px;margin:5px 0 15px;background:var(--bg);border:1px solid var(--b);color:var(--t);border-radius:4px;box-sizing:border-box">
            <input id="inSec" placeholder="Secret Path (Optional)" style="width:100%;padding:8px;margin:5px 0 15px;background:var(--bg);border:1px solid var(--b);color:var(--t);border-radius:4px;box-sizing:border-box">
            <button class="btn btn-p" onclick="App.save()" style="width:100%;padding:8px" id="t-deploy">Deploy</button>
        </div>
        <div class="panel" style="padding:20px">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:15px">
                <h3 style="margin:0" id="t-nodes">Nodes</h3>
                <div>
                    <button onclick="App.export()" class="btn" style="background:var(--b);color:var(--t);padding:4px 8px;font-size:12px" id="t-export">Export</button>
                    <button onclick="document.getElementById('fIn').click()" class="btn" style="background:var(--b);color:var(--t);padding:4px 8px;font-size:12px" id="t-import">Import</button>
                    <input type="file" id="fIn" hidden accept=".json" onchange="App.import(this)">
                </div>
            </div>
            <table style="width:100%;border-collapse:collapse;font-size:13px"><tbody id="list"></tbody></table>
        </div>
    </div>
    
    <div style="margin-top:20px;padding:20px;text-align:center;border-top:1px solid var(--b)">
        <a href="https://github.com/axuitomo/CF-EMBY-PROXY-UI" target="_blank" title="GitHub Repository" style="display:inline-block">
            <svg class="gh-icon" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
        </a>
    </div>

    <script>
        const $=(s)=>document.querySelector(s);
        const API={req:async(d)=>{const r=await fetch('/admin',{method:'POST',body:JSON.stringify(d)});if(r.status===401)location.reload();return r.json()}};
        
        // [V16.1] Language Dictionary & Auto-detection Logic
        const TEXTS = {
            'en': {
                new: "New Node", namePh: "Name (e.g. HK)", targetPh: "Target (http://1.2.3.4:8096)",
                secPh: "Secret Path (Optional)", deploy: "Deploy", nodes: "Nodes",
                export: "Export", import: "Import", noNodes: "No nodes", copy: "Click to Copy Link", copied: "Copied!", del: "Del"
            },
            'zh-Hans': {
                new: "新建节点", namePh: "名称 (例如 HK)", targetPh: "目标地址 (http://1.2.3.4:8096)",
                secPh: "私密路径 (可选)", deploy: "部署", nodes: "节点列表",
                export: "导出配置", import: "导入配置", noNodes: "暂无节点", copy: "点击复制链接", copied: "已复制!", del: "删除"
            },
            'zh-Hant': {
                new: "新建節點", namePh: "名稱 (例如 HK)", targetPh: "目標地址 (http://1.2.3.4:8096)",
                secPh: "私密路徑 (可選)", deploy: "部署", nodes: "節點列表",
                export: "導出配置", import: "導入配置", noNodes: "暫無節點", copy: "點擊複製鏈接", copied: "已複製!", del: "刪除"
            }
        };

        const App={
            nodes:[],
            lang: 'en',
            
            async init(){
                // [V16.1] Auto-detect Browser Language
                const nav = navigator.language.toLowerCase();
                if (nav.includes('tw') || nav.includes('hk')) {
                    this.lang = 'zh-Hant'; // Taiwan/Hong Kong -> Traditional
                } else if (nav.includes('zh')) {
                    this.lang = 'zh-Hans'; // China/other Chinese -> Simplified
                } else {
                    this.lang = 'en';      // Others -> English
                }

                this.updateTexts();
                await this.refresh();
                setInterval(()=>$('#clk').innerText=new Date().toLocaleTimeString('zh-CN',{timeZone:'Asia/Shanghai'}),1000);
            },
            
            // [V16.1] Toggle Language Cycle: En -> Simplified -> Traditional
            toggleLang() {
                if (this.lang === 'en') this.lang = 'zh-Hans';
                else if (this.lang === 'zh-Hans') this.lang = 'zh-Hant';
                else this.lang = 'en';
                
                this.updateTexts();
                this.renderList();
            },
            
            // [V16.1] Apply Translations
            updateTexts() {
                const t = TEXTS[this.lang];
                $('#t-new').innerText = t.new;
                $('#inName').placeholder = t.namePh;
                $('#inTarget').placeholder = t.targetPh;
                $('#inSec').placeholder = t.secPh;
                $('#t-deploy').innerText = t.deploy;
                $('#t-nodes').innerText = t.nodes;
                $('#t-export').innerText = t.export;
                $('#t-import').innerText = t.import;
            },

            async refresh(){
                const d=await API.req({action:'list'});this.nodes=d.nodes;
                this.renderList();
            },
            
            renderList() {
                const t = TEXTS[this.lang];
                $('#list').innerHTML=this.nodes.map(n=>\`<tr><td style="padding:10px;border-bottom:1px solid var(--b)"><b>\${n.name}</b> \${n.secret?'<span style="font-size:10px;padding:2px 4px;background:#d9770633;color:#d97706;border-radius:2px">SEC</span>':''}</td><td style="padding:10px;border-bottom:1px solid var(--b)"><span style="cursor:pointer;font-family:monospace;color:var(--ts)" onclick="App.copy('\${location.origin}/\${n.name}\${n.secret?'/'+n.secret:''}',this)">\${t.copy}</span></td><td style="padding:10px;border-bottom:1px solid var(--b);text-align:right"><button onclick="App.del('\${n.name}')" class="btn" style="color:var(--e);background:transparent">\${t.del}</button></td></tr>\`).join('')||\`<tr><td style="padding:20px;text-align:center;color:var(--ts)">\${t.noNodes}</td></tr>\`;
            },

            async save(){const name=$('#inName').value,target=$('#inTarget').value,secret=$('#inSec').value;if(!name||!target)return alert('Required');await API.req({action:'save',name,target,secret});$('#inName').value='';$('#inTarget').value='';$('#inSec').value='';this.refresh()},
            async del(n){if(confirm('Del?')){await API.req({action:'delete',name:n});this.refresh()}},
            async export(){const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([JSON.stringify(this.nodes)],{type:'json'}));a.download='nodes.json';a.click()},
            async import(e){const f=e.files[0];if(!f)return;const r=new FileReader();r.onload=async ev=>{try{await API.req({action:'import',nodes:JSON.parse(ev.target.result)});this.refresh()}catch{alert('Err')}};r.readAsText(f)},
            copy(t,e){
                navigator.clipboard.writeText(t);
                const o=e.innerText;
                e.innerText=TEXTS[this.lang].copied;
                setTimeout(()=>e.innerText=o,1000)
            }
        };
        App.init();
    </script>
</body></html>`;
        return new Response(html, { headers: { "Content-Type": "text/html" } });
    }
};

// ============================================================================
// 5. MAIN ENTRY (Hot Path Optimized)
// ============================================================================
export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        // 快速分割路径，去除空值
        const segments = url.pathname.split('/').filter(Boolean).map(decodeURIComponent);
        const root = segments[0];

        // 1. 管理后台
        if (root === "admin") {
            const ct = request.headers.get("content-type") || "";
            if (request.method === "POST" && ct.includes("form")) return Auth.handleLogin(request, env);
            if (!(await Auth.verifyRequest(request, env))) {
                if (request.method === "POST") return new Response("Unauthorized", { status: 401 });
                return UI.renderLoginPage();
            }
            if (request.method === "POST") return Database.handleApi(request, env);
            return UI.renderAdminUI();
        }

        // 2. 代理服务
        if (root) {
            // Hot Path: 尝试从 L1/L2/L3 获取节点配置
            const nodeData = await Database.getNode(root, env, ctx);

            if (nodeData) {
                const secret = nodeData.secret;
                let valid = true;
                let strip = 1;

                // 私密路径验证
                if (secret) {
                    if (segments[1] === secret) { strip = 2; }
                    else { valid = false; }
                }

                if (valid) {
                    const remaining = "/" + segments.slice(strip).join('/');
                    // 根路径自动跳转到 Web 界面
                    if (remaining === "/" || remaining === "") {
                        const base = secret ? `/${root}/${secret}` : `/${root}`;
                        return Response.redirect(url.origin + base + "/web/index.html", 302);
                    }
                    return Proxy.handle(request, nodeData, remaining, root, secret);
                }
            }
        }

        return new Response("Access Denied", { status: 403 });
    }
};