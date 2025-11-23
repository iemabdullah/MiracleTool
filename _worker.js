import { connect } from "cloudflare:sockets";
let config_JSON, reverse proxy IP = '', enable SOCKS5 reverse proxy = null, enable global SOCKS5 reverse proxy = false, my SOCKS5 account = '', parsedSocks5Address = {};
let SOCKS5 whitelist = ['*tapecontent.net', '*cloudatacdn.com', '*loadshare.org', '*cdn-centaurus.com', 'scholar.google.com'];
const Pages static page = 'https://edt-pages.github.io';
/// ...
export default {
    async fetch(request, env) {
        const url = new URL(request.url);
        const UA = request.headers.get('User-Agent') || 'null';
        const upgradeHeader = request.headers.get('Upgrade');
        `const administrator password = env.ADMIN || env.admin || env.PASSWORD || env.password || env.pswd || env.TOKEN || env.KEY;`
        const encryption key = env.KEY || 'Do not change this default key. Please modify it yourself by adding the variable KEY if needed';
        const userIDMD5 = await MD5MD5(administrator password + encryption key);
        const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
        const envUUID = env.UUID || env.uuid;
        const userID = (envUUID && uuidRegex.test(envUUID)) ? envUUID.toLowerCase() : [userIDMD5.slice(0, 8), userIDMD5.slice(8, 12), '4' + userIDMD5.slice(13, 16), userIDMD5.slice(16, 20), userIDMD5.slice(20)].join('-');
        const host = env.HOST ? env.HOST.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0] : url.hostname;
        if (env.PROXYIP) {
            const proxyIPs = await Organize into an array (env.PROXYIP);
            Anti-generation IP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
        } else reverse generation IP = (request.cf.colo + '.PrOxYIp.CmLiUsSsS.nEt').toLowerCase();
        const access IP = request.headers.get('X-Real-IP') || request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || request.headers.get('True-Client-IP') || request.headers.get('Fly-Client-IP') || request.headers.get('X-Appengine-Remote-Addr') || request.headers.get('X-Forwarded-For') || request.headers.get('X-Real-IP') || request.headers.get('X-Cluster-Client-IP') || request.cf?.clientTcpRtt || 'Unknown IP';
        If `(env.GO2SOCKS5) SOCKS5 whitelist = await`, then organize the data into an array `(env.GO2SOCKS5)`.
        if (!upgradeHeader || upgradeHeader !== 'websocket') {
            if (url.protocol === 'http:') return Response.redirect(url.href.replace(`http://${url.hostname}`, `https://${url.hostname}`), 301);
            if (!Administrator password) return fetch(Pages static page + '/noADMIN').then(r => { const headers = new Headers(r.headers); headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate'); headers.set('Pragma', 'no-cache'); headers.set('Expires', '0'); return new Response(r.body, { status: 404, statusText: r.statusText, headers }); });
            if (!env.KV) return fetch(Pages static page + '/noKV').then(r => { const headers = new Headers(r.headers); headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate'); headers.set('Pragma', 'no-cache'); headers.set('Expires', '0'); return new Response(r.body, { status: 404, statusText: r.statusText, headers }); });
            const access path = url.pathname.slice(1).toLowerCase();
            const case-sensitive access path = url.pathname.slice(1);
            if (Access path === Encryption key && Encryption key !== 'Do not change this default key; please modify it yourself by adding the variable KEY if needed') {//Quick subscription
                const params = new URLSearchParams(url.search);
                params.set('token', await MD5MD5(host + userID));
                return new Response('Redirecting...', { status: 302, headers: { 'Location': `/sub?${params.toString()}` } });
            } else if (access path === 'login') { // Handle login page and login request
                const cookies = request.headers.get('Cookie') || '';
                const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
                if (authCookie == await MD5MD5(UA + encryption key + administrator password)) return new Response('Redirecting...', { status: 302, headers: { 'Location': '/admin' } });
                if (request.method === 'POST') {
                    const formData = await request.text();
                    const params = new URLSearchParams(formData);
                    const Enter password = params.get('password');
                    if (enter password === administrator password) {
                        // Password correct, set cookie and return a success flag.
                        const response = new Response(JSON.stringify({ success: true }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                        The response headers are set to 'Set-Cookie', with the following headers: `auth=${await MD5MD5(UA + encryption key + administrator password)}; Path=/; Max-Age=86400; HttpOnly`);
                        return response;
                    }
                }
                return fetch(Pages static pages + '/login');
            } else if (access path == 'admin' || access path.startsWith('admin/')) { // Respond to the management page after verifying the cookie
                const cookies = request.headers.get('Cookie') || '';
                const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
                // No cookie or cookie error, redirect to /login page
                if (!authCookie || authCookie !== await MD5MD5(UA + encryption key + administrator password)) return new Response('Redirecting...', { status: 302, headers: { 'Location': '/login' } });
                if (access path === 'admin/log.json') { // Read log content
                    `const env.KV.get('log.json') || '[]';` This code retrieves the log file content using the `await env.KV.get('log.json')` function.
                    The function returns a new Response("Read log content", { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                } else if (case-sensitive access path === 'admin/getCloudflareUsage') { // Query request count
                    try {
                        const Usage_JSON = await getCloudflareUsage(url.searchParams.get('Email'), url.searchParams.get('GlobalAPIKey'), url.searchParams.get('AccountID'), url.searchParams.get('APIToken'));
                        return new Response(JSON.stringify(Usage_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json' } });
                    } catch (err) {
                        const errorResponse = { msg: 'Query request failed, reason for failure:' + err.message, error: err.message };
                        return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                    }
                } else if (case-sensitive access path === 'admin/getADDAPI') { // Verify preferred API
                    if (url.searchParams.get('url')) {
                        const preferred URL to be verified = url.searchParams.get('url');
                        try {
                            new URL(preferred URL to be verified);
                            const preferredAPI IP = await RequestPreferredAPI([preferred URL to be verified], url.searchParams.get('port') || '443');
                            return new Response(JSON.stringify({ success: true, data: preferred API IP }, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                        } catch (err) {
                            const errorResponse = { msg: 'Verification of the preferred API failed, reason for failure:' + err.message, error: err.message };
                            return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                        }
                    }
                    return new Response(JSON.stringify({ success: false, data: [] }, null, 2), { status: 403, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                } else if (access path === 'admin/check') {// SOCKS5 proxy check
                    `let` checks the proxy response;
                    if (url.searchParams.has('socks5')) {
                        Detect proxy response = await SOCKS5 availability verification('socks5', url.searchParams.get('socks5'));
                    } else if (url.searchParams.has('http')) {
                        Detect proxy response = await SOCKS5 availability verification('http', url.searchParams.get('http'));
                    } else {
                        The code returns a new Response(JSON.stringify({ error: 'Missing Proxy Parameter' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                    }
                    return new Response(JSON.stringify("Detect proxy response", null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                }

                `config_JSON = await` reads `config_JSON(env, host, userID);`

                if (access path === 'admin/init') { // Reset configuration to default value
                    try {
                        config_JSON = await reads config_JSON(env, host, userID, true);
                        The `await` function logs requests (env, request, accessing IP, 'Init_Config', config_JSON).
                        config_JSON.init = 'Configuration has been reset to default values';
                        return new Response(JSON.stringify(config_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                    } catch (err) {
                        const errorResponse = { msg: 'Configuration reset failed, reason for failure: ' + err.message, error: err.message };
                        return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                    }
                } else if (request.method === 'POST') {// Handle key-value operations (POST requests)
                    if (access path === 'admin/config.json') { // Save config.json configuration
                        try {
                            const newConfig = await request.json();
                            // Verify configuration integrity
                            if (!newConfig.UUID || !newConfig.HOST) return new Response(JSON.stringify({ error: 'Incomplete configuration' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });

                            // Save to KV
                            await env.KV.put('config.json', JSON.stringify(newConfig, null, 2));
                            The `await` function logs requests using the following method: `env, request, accessing IP, 'Save_Config', config_JSON`.
                            return new Response(JSON.stringify({ success: true, message: 'Configuration saved' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                        } catch (error) {
                            console.error('Failed to save configuration:', error);
                            return new Response(JSON.stringify({ error: 'Failed to save configuration: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                        }
                    } else if (access path === 'admin/cf.json') { // Save cf.json configuration
                        try {
                            const newConfig = await request.json();
                            const CF_JSON = { Email: null, GlobalAPIKey: null, AccountID: null, APIToken: null };
                            if (!newConfig.init || newConfig.init !== true) {
                                if (newConfig.Email && newConfig.GlobalAPIKey) {
                                    CF_JSON.Email = newConfig.Email;
                                    CF_JSON.GlobalAPIKey = newConfig.GlobalAPIKey;
                                    CF_JSON.AccountID = null;
                                    CF_JSON.APIToken = null;
                                } else if (newConfig.AccountID && newConfig.APIToken) {
                                    CF_JSON.Email = null;
                                    CF_JSON.GlobalAPIKey = null;
                                    CF_JSON.AccountID = newConfig.AccountID;
                                    CF_JSON.APIToken = newConfig.APIToken;
                                } else {
                                    The code returns a new Response(JSON.stringify({ error: 'Incomplete configuration' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                                }
                            }

                            // Save to KV
                            await env.KV.put('cf.json', JSON.stringify(CF_JSON, null, 2));
                            The `await` function logs requests using the following method: `env, request, accessing IP, 'Save_Config', config_JSON`.
                            return new Response(JSON.stringify({ success: true, message: 'Configuration saved' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                        } catch (error) {
                            console.error('Failed to save configuration:', error);
                            return new Response(JSON.stringify({ error: 'Failed to save configuration: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                        }
                    } else if (access path === 'admin/tg.json') { // Save tg.json configuration
                        try {
                            const newConfig = await request.json();
                            if (newConfig.init && newConfig.init === true) {
                                const TG_JSON = { BotToken: null, ChatID: null };
                                await env.KV.put('tg.json', JSON.stringify(TG_JSON, null, 2));
                            } else {
                                if (!newConfig.BotToken || !newConfig.ChatID) return new Response(JSON.stringify({ error: 'Incomplete configuration' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                                await env.KV.put('tg.json', JSON.stringify(newConfig, null, 2));
                            }
                            The `await` function logs requests using the following method: `env, request, accessing IP, 'Save_Config', config_JSON`.
                            return new Response(JSON.stringify({ success: true, message: 'Configuration saved' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                        } catch (error) {
                            console.error('Failed to save configuration:', error);
                            return new Response(JSON.stringify({ error: 'Failed to save configuration: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                        }
                    } else if (case-sensitive access path === 'admin/ADD.txt') { // Save custom preferred IP
                        try {
                            const customIPs = await request.text();
                            await env.KV.put('ADD.txt', customIPs); // Save to KV
                            The `await` function logs requests using the following method: `(env, request, accessing IP, 'Save_Custom_IPs', config_JSON)`.
                            The code returns a new Response(JSON.stringify({ success: true, message: 'Custom IP saved' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                        } catch (error) {
                            console.error('Failed to save custom IP:', error);
                            The code returns a new Response(JSON.stringify({ error: 'Failed to save custom IP: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                        }
                    } else return new Response(JSON.stringify({ error: 'Unsupported POST request path' }), { status: 404, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                } else if (access path === 'admin/config.json') { // Process the admin/config.json request and return JSON
                    return new Response(JSON.stringify(config_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json' } });
                } else if (case-sensitive access path === 'admin/ADD.txt') { // Process the admin/ADD.txt request and return the local preferred IP address.
                    let local preferred IP = await env.KV.get('ADD.txt') || 'null';
                    if (local preferred IP == 'null') local preferred IP = (await generate random IP(request, config_JSON.preferred subscription generation.local IP library.random number, config_JSON.preferred subscription generation.local IP library.specified port))[1];
                    return new Response(local preferred IP, { status: 200, headers: { 'Content-Type': 'text/plain;charset=utf-8', 'asn': request.cf.asn } });
                } else if (access path === 'admin/cf.json') { // CF configuration file
                    return new Response(JSON.stringify(request.cf, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                }

                The `await` function requests logging (env, request, access IP, 'Admin_Login', config_JSON).
                return fetch(Pages static pages + '/admin');
            } else if (access path === 'logout') { // Clear cookies and redirect to the login page
                const response = new Response('Redirecting...', { status: 302, headers: { 'Location': '/login' } });
                Response.headers.set('Set-Cookie', 'auth=; Path=/; Max-Age=0; HttpOnly');
                return response;
            } else if (access path === 'sub') { // Handle subscription requests
                const subscriptionTOKEN = await MD5MD5(host + userID);
                if (url.searchParams.get('token') === Subscribe to TOKEN) {
                    `config_JSON = await` reads `config_JSON(env, host, userID);`
                    The `await` function logs requests using the following method: `(env, request, accessing IP, 'Get_SUB', config_JSON)`.
                    const ua = UA.toLowerCase();
                    const expire = 4102329600; // Expiration date: 2099-12-31
                    const now = Date.now();
                    const today = new Date(now);
                    today.setHours(0, 0, 0, 0);
                    const UD = Math.floor(((now - today.getTime()) / 86400000) * 24 * 1099511627776 / 2);
                    let pagesSum = UD, workersSum = UD, total = 24 * 1099511627776;
                    if (config_JSON.CF.Usage.success) {
                        pagesSum = config_JSON.CF.Usage.pages;
                        workersSum = config_JSON.CF.Usage.workers;
                        total = 1024 * 100;
                    }
                    const responseHeaders = {
                        "content-type": "text/plain; charset=utf-8",
                        "Profile-Update-Interval": config_JSON.preferred_subscription_generation.SUBUpdateTime,
                        "Profile-web-page-url": url.protocol + '//' + url.host + '/admin',
                        "Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`,
                        "Cache-Control": "no-store",
                    };
                    const isSubConverterRequest = request.headers.has('b64') || request.headers.has('base64') || request.headers.get('subconverter-request') || request.headers.get('subconverter-version') || ua.includes('subconverter') || ua.includes(('CF-Workers-SUB').toLowerCase());
                    const subscription type = isSubConverterRequest
                        'mixed'
                        : url.searchParams.has('target')
                            ? url.searchParams.get('target')
                            : url.searchParams.has('clash') || ua.includes('clash') || ua.includes('meta') || ua.includes('mihomo')
                                'clash'
                                : url.searchParams.has('sb') || url.searchParams.has('singbox') || ua.includes('singbox') || ua.includes('sing-box')
                                    'singbox'
                                    : url.searchParams.has('surge') || ua.includes('surge')
                                        ? 'surge&ver=4'
                                        : 'mixed';

                    if (!ua.includes('mozilla')) responseHeaders["Content-Disposition"] = `attachment; filename*=utf-8''${encodeURIComponent(config_JSON.preferredsubscriptiongen.SUBNAME)}`;
                    const protocol_type = (url.searchParams.has('surge') || ua.includes('surge')) ? 'tro' + 'jan' : config_JSON.protocol_type;
                    let Subscribe to content = '';
                    if (subscription type === 'mixed') {
                        const node path = config_JSON.enabled0RTT ? config_JSON.PATH + '?ed=2560' : config_JSON.PATH;
                        const TLS fragmentation parameter = config_JSON.TLS fragment == 'Shadowrocket' ? `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}` : config_JSON.TLS fragment == 'Happ' ? `&fragment=${encodeURIComponent('3,1,tlshello')}` : '';
                        const complete preferred list = config_JSON.preferred subscription generation.local IP library.random IP ? (await generate random IP(request, config_JSON.preferred subscription generation.local IP library.random number, config_JSON.preferred subscription generation.local IP library.specified port))[0] : await env.KV.get('ADD.txt') ? await organize into array(await env.KV.get('ADD.txt')) : (await generate random IP(request, config_JSON.preferred subscription generation.local IP library.random number, config_JSON.preferred subscription generation.local IP library.specified port))[0];
                        const Preferred API = [], Preferred IP = [], Other Nodes = [];
                        for (const element of complete preferred list) {
                            if (element.toLowerCase().startsWith('https://')) preferredAPI.push(element);
                            else if (element.toLowerCase().includes('://')) other nodes.push(element);
                            else, the preferred option is IP.push(element);
                        }
                        const OtherNodesLINK = OtherNodes.join('\n') + '\n';
                        if (!url.searchParams.has('sub') && config_JSON.preferred_subscription_generator.local) { // Generate subscription locally
                            const preferredAPI_IP = await request_preferredAPI(preferredAPI);
                            const Fully Optimized IP = [...new Set(Optimized IP.concat(Optimized API's IP))];
                            Subscription content = Complete preferred IP.map(original address => {
                                // Uniform regular expression: Matches domain name/IPv4/IPv6 address + optional port + optional comments
                                // Example:
                                // - Domain: hj.xmm1993.top:2096#notes or example.com
                                // - IPv4: 166.0.188.128:443#Los Angeles or 166.0.188.128
                                // - IPv6: [2606:4700::]:443#CMCC or [2606:4700::]
                                const regex = /^(\[[\da-fA-F:]+\]|[\d.]+|[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(? :\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*)(?::(\d+))?(?:#(.+))?$/;
                                const match = original address.match(regex);

                                let node address, node port = "443", node comment;

                                if (match) {
                                    Node address = match[1]; // IP address or domain name (may include square brackets)
                                    Node port = match[2] || "443"; // Port, default 443
                                    Node comment = match[3] || node address; // comment, defaults to the address itself
                                } else {
                                    // Irregular format, skip processing and return null
                                    console.warn(`[Subscription content] Irregular IP format has been ignored: ${original address}`);
                                    return null;
                                }
                                const nodeHOST = random wildcard replacement(host);
                                return `${protocol type}://${config_JSON.UUID}@${node address}:${node port}?security=tls&type=${config_JSON.transport protocol}&host=${node HOST}&sni=${node HOST}&path=${encodeURIComponent(config_JSON.random path?random path() + node path: node path) + TLS fragmentation parameter}&encryption=none${config_JSON.skip certificate verification?'&allowInsecure=1' : ''}#${encodeURIComponent(node ​​comment)}`;
                            }).filter(item => item !== null).join('\n');
                            Subscription content = btoa(other node LINK + subscription content);
                        } else { // Preferred subscription generator
                            let 'Preferred Subscription Generator' HOST = url.searchParams.get('sub') || config_JSON.PreferredSubscriptionGenerator.SUB;
                            Preferred Subscription Generator HOST = Preferred Subscription Generator HOST && !/^https?:\/\//i.test(Preferred Subscription Generator HOST) ? `https://${Preferred Subscription Generator HOST}` : Preferred Subscription Generator HOST;
                            const Preferred Subscription Generator URL = `${Preferred Subscription Generator HOST}/sub?host=example.com&${Protocol Type=== ('v' + 'le' + 'ss') ? 'uuid' : 'pw'}=00000000-0000-4000-8000-000000000000&path=${encodeURIComponent(config_JSON.randomPath?randomPath() + NodePath: NodePath) + TLSFragmentationParameters}&type=${config_JSON.TransportProtocol}`;
                            try {
                                const response = await fetch(preferred subscription generator URL, { headers: { 'User-Agent': 'v2rayN/edge' + 'tunnel (https://github.com/cmliu/edge' + 'tunnel)' } });
                                if (response.ok) Subscribed content = btoa(other nodes LINK + atob(await response.text()));
                                else return new Response('Preferred subscription generator exception: ' + response.statusText, { status: response.status });
                            } catch (error) {
                                return new Response('Preferred Subscription Generator Error: ' + error.message, { status: 403 });
                            }
                        }
                    } else { // Subscription conversion
                        const Subscription conversion URL = `${config_JSON.subscription conversion configuration.SUBAPI}/sub?target=${subscription type}&url=${encodeURIComponent(url.protocol + '//' + url.host + '/sub?target=mixed&token=' + subscription TOKEN + (url.searchParams.has('sub') && url.searchParams.get('sub') != '' ? `&sub=${url.searchParams.get('sub')}` : ''))}&config=${encodeURIComponent(config_JSON.subscription conversion configuration.SUBCONFIG)}&emoji=${config_JSON.subscription conversion configuration.SUBEMOJI}&scv=${config_JSON.skip certificate verification}`;
                        try {
                            const response = await fetch(subscription conversion URL, { headers: { 'User-Agent': 'Subconverter for ' + subscription type + ' edge' + 'tunnel(https://github.com/cmliu/edge' + 'tunnel)' } });
                            if (response.ok) {
                                Subscribed content = await response.text();
                                If (url.searchParams.has('surge') || ua.includes('surge')) Subscription content = surge(subscription content, url.protocol + '//' + url.host + '/sub?token=' + subscription TOKEN + '&surge', config_JSON);
                            } else return new Response('Subscription conversion backend exception: ' + response.statusText, { status: response.status });
                        } catch (error) {
                            return new Response('Subscription conversion backend error: ' + error.message, { status: 403 });
                        }
                    }
                    if (subscription type === 'mixed') {
                        Subscription content = Batch replace domains(atob(subscription content).replace(/00000000-0000-4000-8000-000000000000/g, config_JSON.UUID), host);
                        if (!ua.includes('mozilla')) Subscription content = btoa(subscription content);
                    } else Subscription content = Batch replace domain(subscription content.replace(/00000000-0000-4000-8000-000000000000/g, config_JSON.UUID), host);
                    if (subscription type === 'singbox') {
                        Subscription content = JSON.stringify(JSON.parse(subscription content), null, 2);
                        responseHeaders["content-type"] = 'application/json; charset=utf-8';
                    } else if (subscription type === 'clash') {
                        responseHeaders["content-type"] = 'application/x-yaml; charset=utf-8';
                    }
                    return new Response(subscription content, { status: 200, headers: responseHeaders });
                }
                return new Response('Invalid subscription token', { status: 403 });
            } else if (access path === 'locations') return fetch(new Request('https://speed.cloudflare.com/locations'));
        } else if (administrator password) {// ws proxy
            `await` retrieves parameters from the request.
            return `await` to handle the WS request (request, userID);
        }

        let 'nginx' URL = env.URL || 'nginx';
        if (the fake page URL && the fake page URL !== 'nginx' && the fake page URL !== '1101') {
            The fake page URL is set to `fake page URL.trim().replace(/\/$/, '');`
            If (!disguised_page_URL.match(/^https?:\/\//i)) then the disguised_page_URL = 'https://' + the disguised_page_URL;
            if (the fake page URL.toLowerCase().startsWith('http://')) the fake page URL = 'https://' + the fake page URL.substring(7);
            try { const u = new URL("masked page URL"); masked page URL = u.protocol + '//' + u.host; } catch (e) { masked page URL = 'nginx'; }
        }
        If the fake page URL is '1101', return a new Response(await html1101(url.host, accessing IP), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
        try {
            const reverse proxy URL = new URL(masked page URL), new request headers = new Headers(request.headers);
            New request header.set('Host', reverse proxy URL.host);
            If (new request header.has('Referer')) { const u = new URL(new request header.get('Referer')); new request header.set('Referer', reverse proxy URL.protocol + '//' + reverse proxy URL.host + u.pathname + u.search); }
            If (new request header.has('Origin')) new request header.set('Origin', reverse proxy URL.protocol + '//' + reverse proxy URL.host);
            If `new request header.has('User-Agent') && UA && UA !== 'null'`, then `new request header.set('User-Agent', UA)`.
            return fetch(new Request(reverse proxy URL.protocol + reverse proxy URL.host + url.pathname + url.search, { method: request.method, headers: new request headers, body: request.body, cf: request.cf }));
        } catch (error) { }
        return new Response(await nginx(), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
    }
};
///////////////////////////////////////////////////////////////////////WS Data Transmission////////////////////////////////////////////////////////////
The async function handles the WS request (request, yourUUID) {
    const wssPair = new WebSocketPair();
    const [clientSock, serverSock] = Object.values(wssPair);
    serverSock.accept();
    let remoteConnWrapper = { socket: null };
    let isDnsQuery = false;
    const earlyData = request.headers.get('sec-websocket-protocol') || '';
    const readable = makeReadableStr(serverSock, earlyData);
    let check if it's a Trojan horse = null;
    readable.pipeTo(new WritableStream({
        async write(chunk) {
            if (isDnsQuery) return await forwardataudp(chunk, serverSock, null);
            if (remoteConnWrapper.socket) {
                const writer = remoteConnWrapper.socket.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }

            if (check if it's a Trojan horse === null) {
                const bytes = new Uint8Array(chunk);
                Determine if it is a Trojan horse = bytes.byteLength >= 58 && bytes[56] === 0x0d && bytes[57] === 0x0a;
            }

            if (remoteConnWrapper.socket) {
                const writer = remoteConnWrapper.socket.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }

            if (check if it's a Trojan) {
                const { port, hostname, rawClientData } = Parse Trojan request(chunk, yourUUID);
                if (isSpeedTestSite(hostname)) throw new Error('Speedtest site is blocked');
                await forwardataTCP(hostname, port, rawClientData, serverSock, null, remoteConnWrapper);
            } else {
                const { port, hostname, rawIndex, version, isUDP } = Parse Wei Liesi request(chunk, yourUUID);
                if (isSpeedTestSite(hostname)) throw new Error('Speedtest site is blocked');
                if (isUDP) {
                    if (port === 53) isDnsQuery = true;
                    else throw new Error('UDP is not supported');
                }
                const respHeader = new Uint8Array([version[0], 0]);
                const rawData = chunk.slice(rawIndex);
                if (isDnsQuery) return forwardataudp(rawData, serverSock, respHeader);
                await forwardataTCP(hostname, port, rawData, serverSock, respHeader, remoteConnWrapper);
            }
        },
    })).catch((err) => {
        // console.error('Readable pipe error:', err);
    });

    return new Response(null, { status: 101, webSocket: clientSock });
}

function parse Trojan request(buffer, passwordPlainText) {
    const sha224Password = sha224(passwordPlainText);
    if (buffer.byteLength < 56) return { hasError: true, message: "invalid data" };
    let crLfIndex = 56;
    if (new Uint8Array(buffer.slice(56, 57))[0] !== 0x0d || new Uint8Array(buffer.slice(57, 58))[0] !== 0x0a) return { hasError: true, message: "invalid header format" };
    const password = new TextDecoder().decode(buffer.slice(0, crLfIndex));
    if (password !== sha224Password) return { hasError: true, message: "invalid password" };

    const socks5DataBuffer = buffer.slice(crLfIndex + 2);
    if (socks5DataBuffer.byteLength < 6) return { hasError: true, message: "invalid S5 request data" };

    const view = new DataView(socks5DataBuffer);
    const cmd = view.getUint8(0);
    if (cmd !== 1) return { hasError: true, message: "unsupported command, only TCP is allowed" };

    const atype = view.getUint8(1);
    let addressLength = 0;
    let addressIndex = 2;
    let address = "";
    switch (atype) {
        case 1: // IPv4
            addressLength = 4;
            address = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)).join(".");
            break
        case 3: // Domain
            addressLength = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex + 1))[0];
            addressIndex += 1;
            address = new TextDecoder().decode(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength));
            break
        case 4: // IPv6
            addressLength = 16;
            const dataView = new DataView(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength));
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            address = ipv6.join(":");
            break
        default:
            return { hasError: true, message: `invalid addressType is ${atype}` };
    }

    if (!address) {
        return { hasError: true, message: `address is empty, addressType is ${atype}` };
    }

    const portIndex = addressIndex + addressLength;
    const portBuffer = socks5DataBuffer.slice(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);

    return {
        hasError: false,
        addressType: atype,
        port: portRemote,
        hostname: address,
        rawClientData: socks5DataBuffer.slice(portIndex + 4)
    };
}

function parses Wei Lies' request(chunk, token) {
    if (chunk.byteLength < 24) return { hasError: true, message: 'Invalid data' };
    const version = new Uint8Array(chunk.slice(0, 1));
    if (formatIdentifier(new Uint8Array(chunk.slice(1, 17))) !== token) return { hasError: true, message: 'Invalid uuid' };
    const optLen = new Uint8Array(chunk.slice(17, 18))[0];
    const cmd = new Uint8Array(chunk.slice(18 + optLen, 19 + optLen))[0];
    let isUDP = false;
    if (cmd === 1) { } else if (cmd === 2) { isUDP = true; } else { return { hasError: true, message: 'Invalid command' }; }
    const portIdx = 19 + optLen;
    const port = new DataView(chunk.slice(portIdx, portIdx + 2)).getUint16(0);
    let addrIdx = portIdx + 2, addrLen = 0, addrValIdx = addrIdx + 1, hostname = '';
    const addressType = new Uint8Array(chunk.slice(addrIdx, addrValIdx))[0];
    switch (addressType) {
        case 1:
            addrLen = 4;
            hostname = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + addrLen)).join('.');
            break
        case 2:
            addrLen = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + 1))[0];
            addrValIdx += 1;
            hostname = new TextDecoder().decode(chunk.slice(addrValIdx, addrValIdx + addrLen));
            break
        case 3:
            addrLen = 16;
            const ipv6 = [];
            const ipv6View = new DataView(chunk.slice(addrValIdx, addrValIdx + addrLen));
            for (let i = 0; i < 8; i++) ipv6.push(ipv6View.getUint16(i * 2).toString(16));
            hostname = ipv6.join(':');
            break
        default:
            return { hasError: true, message: `Invalid address type: ${addressType}` };
    }
    if (!hostname) return { hasError: true, message: `Invalid address: ${addressType}` };
    return { hasError: false, addressType, port, hostname, isUDP, rawIndex: addrValIdx + addrLen, version };
}
async function forwardataTCP(host, portNum, rawData, ws, respHeader, remoteConnWrapper) {
    console.log(JSON.stringify({ configJSON: { Target address: host, Target port: portNum, Reverse proxy IP: Reverse proxy IP, Proxy type: Enable SOCKS5 reverse proxy, Global proxy: Enable SOCKS5 global reverse proxy, Proxy account: My SOCKS5 account} }));
    async function connectDirect(address, port, data) {
        const remoteSock = connect({ hostname: address, port: port });
        const writer = remoteSock.writable.getWriter();
        await writer.write(data);
        writer.releaseLock();
        return remoteSock;
    }
    async function connecttoPry() {
        let newSocket;
        if (enabled SOCKS5 reverse proxy === 'socks5') {
            newSocket = await socks5Connect(host, portNum, rawData);
        } else if (Enable SOCKS5 reverse proxy === 'http' || Enable SOCKS5 reverse proxy === 'https') {
            newSocket = await httpConnect(host, portNum, rawData);
        } else {
            try {
                const [reverse proxy IP address, reverse proxy IP port] = await resolve address port(reverse proxy IP);
                newSocket = await connectDirect(reverse proxy IP address, reverse proxy IP port, rawData);
            } catch { newSocket = await connectDirect(atob('UFJPWFlJUC50cDEuMDkwMjI3Lnh5eg=='), 1, rawData) }
        }
        remoteConnWrapper.socket = newSocket;
        newSocket.closed.catch(() => { }).finally(() => closeSocketQuietly(ws));
        connectStreams(newSocket, ws, respHeader, null);
    }

    if (Enable SOCKS5 reverse proxy && Enable SOCKS5 global reverse proxy) {
        try {
            await connecttoPry();
        } catch (err) {
            throw err;
        }
    } else {
        try {
            const initialSocket = await connectDirect(host, portNum, rawData);
            remoteConnWrapper.socket = initialSocket;
            connectStreams(initialSocket, ws, respHeader, connecttoPry);
        } catch (err) {
            await connecttoPry();
        }
    }
}

async function forwardataudp(udpChunk, webSocket, respHeader) {
    try {
        const tcpSocket = connect({ hostname: '8.8.4.4', port: 53 });
        let vlessHeader = respHeader;
        const writer = tcpSocket.writable.getWriter();
        await writer.write(udpChunk);
        writer.releaseLock();
        await tcpSocket.readable.pipeTo(new WritableStream({
            async write(chunk) {
                if (webSocket.readyState === WebSocket.OPEN) {
                    if (vlessHeader) {
                        const response = new Uint8Array(vlessHeader.length + chunk.byteLength);
                        response.set(vlessHeader, 0);
                        response.set(chunk, vlessHeader.length);
                        webSocket.send(response.buffer);
                        vlessHeader = null;
                    } else {
                        webSocket.send(chunk);
                    }
                }
            },
        }));
    } catch (error) {
        // console.error('UDP forward error:', error);
    }
}

function closeSocketQuietly(socket) {
    try {
        if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
            socket.close();
        }
    } catch (error) { }
}

function formatIdentifier(arr, offset = 0) {
    const hex = [...arr.slice(offset, offset + 16)].map(b => b.toString(16).padStart(2, '0')).join('');
    return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}`;
}
async function connectStreams(remoteSocket, webSocket, headerData, retryFunc) {
    let header = headerData, hasData = false;
    await remoteSocket.readable.pipeTo(
        new WritableStream({
            async write(chunk, controller) {
                hasData = true;
                if (webSocket.readyState !== WebSocket.OPEN) controller.error('ws.readyState is not open');
                if (header) {
                    const response = new Uint8Array(header.length + chunk.byteLength);
                    response.set(header, 0);
                    response.set(chunk, header.length);
                    webSocket.send(response.buffer);
                    header = null;
                } else {
                    webSocket.send(chunk);
                }
            },
            abort() { },
        })
    ).catch((err) => {
        closeSocketQuietly(webSocket);
    });
    if (!hasData && retryFunc) {
        await retryFunc();
    }
}

function makeReadableStr(socket, earlyDataHeader) {
    let cancelled = false;
    return new ReadableStream({
        start(controller) {
            socket.addEventListener('message', (event) => {
                if (!cancelled) controller.enqueue(event.data);
            });
            socket.addEventListener('close', () => {
                if (!cancelled) {
                    closeSocketQuietly(socket);
                    controller.close();
                }
            });
            socket.addEventListener('error', (err) => controller.error(err));
            const { earlyData, error } = base64ToArray(earlyDataHeader);
            if (error) controller.error(error);
            else if (earlyData) controller.enqueue(earlyData);
        },
        cancel() {
            cancelled = true)
            closeSocketQuietly(socket);
        }
    });
}

function isSpeedTestSite(hostname) {
    const speedTestDomains = [atob('c3BlZWQuY2xvdWRmbGFyZS5jb20=')];
    if (speedTestDomains.includes(hostname)) {
        return true;
    }

    for (const domain of speedTestDomains) {
        if (hostname.endsWith('.' + domain) || hostname === domain) {
            return true;
        }
    }
    return false;
}

function base64ToArray(b64Str) {
    if (!b64Str) return { error: null };
    try {
        const binaryString = atob(b64Str.replace(/-/g, '+').replace(/_/g, '/'));
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return { earlyData: bytes.buffer, error: null };
    } catch (error) {
        return { error };
    }
}
////////////////////////////////SOCKS5/HTTP Functions///////////////////////////////////////////////////////
async function socks5Connect(targetHost, targetPort, initialData) {
    const { username, password, hostname, port } = parsedSocks5Address;
    const socket = connect({ hostname, port }), writer = socket.writable.getWriter(), reader = socket.readable.getReader();
    try {
        const authMethods = username && password ? new Uint8Array([0x05, 0x02, 0x00, 0x02]) : new Uint8Array([0x05, 0x01, 0x00]);
        await writer.write(authMethods);
        let response = await reader.read();
        if (response.done || response.value.byteLength < 2) throw new Error('S5 method selection failed');

        const selectedMethod = new Uint8Array(response.value)[1];
        if (selectedMethod === 0x02) {
            if (!username || !password) throw new Error('S5 requires authentication');
            const userBytes = new TextEncoder().encode(username), passBytes = new TextEncoder().encode(password);
            const authPacket = new Uint8Array([0x01, userBytes.length, ...userBytes, passBytes.length, ...passBytes]);
            await writer.write(authPacket);
            response = await reader.read();
            if (response.done || new Uint8Array(response.value)[1] !== 0x00) throw new Error('S5 authentication failed');
        } else if (selectedMethod !== 0x00) throw new Error(`S5 unsupported auth method: ${selectedMethod}`);

        const hostBytes = new TextEncoder().encode(targetHost);
        const connectPacket = new Uint8Array([0x05, 0x01, 0x00, 0x03, hostBytes.length, ...hostBytes, targetPort >> 8, targetPort & 0xff]);
        await writer.write(connectPacket);
        response = await reader.read();
        if (response.done || new Uint8Array(response.value)[1] !== 0x00) throw new Error('S5 connection failed');

        await writer.write(initialData);
        writer.releaseLock(); reader.releaseLock();
        return socket;
    } catch (error) {
        try { writer.releaseLock(); } catch (e) { }
        try { reader.releaseLock(); } catch (e) { }
        try { socket.close(); } catch (e) { }
        throw error?
    }
}

async function httpConnect(targetHost, targetPort, initialData) {
    const { username, password, hostname, port } = parsedSocks5Address;
    const socket = connect({ hostname, port }), writer = socket.writable.getWriter(), reader = socket.readable.getReader();
    try {
        const auth = username && password ? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n` : '';
        const request = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n${auth}User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n`;
        await writer.write(new TextEncoder().encode(request));

        let responseBuffer = new Uint8Array(0), headerEndIndex = -1, bytesRead = 0;
        while (headerEndIndex === -1 && bytesRead < 8192) {
            const { done, value } = await reader.read();
            if (done) throw new Error('Connection closed before receiving HTTP response');
            responseBuffer = new Uint8Array([...responseBuffer, ...value]);
            bytesRead = responseBuffer.length;
            const crlfcrlf = responseBuffer.findIndex((_, i) => i < responseBuffer.length - 3 && responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a && responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a);
            if (crlfcrlf !== -1) headerEndIndex = crlfcrlf + 4;
        }

        if (headerEndIndex === -1) throw new Error('Invalid HTTP response');
        const statusCode = parseInt(new TextDecoder().decode(responseBuffer.slice(0, headerEndIndex)).split('\r\n')[0].match(/HTTP\/\d\.\d\s+(\d+)/)[1]);
        if (statusCode < 200 || statusCode >= 300) throw new Error(`Connection failed: HTTP ${statusCode}`);

        await writer.write(initialData);
        writer.releaseLock(); reader.releaseLock();
        return socket;
    } catch (error) {
        try { writer.releaseLock(); } catch (e) { }
        try { reader.releaseLock(); } catch (e) { }
        try { socket.close(); } catch (e) { }
        throw error?
    }
}
/// ...
function surge(content, url, config_JSON) {
    let each line of content;
    if (content.includes('\r\n')) {
        Each line of content = content.split('\r\n');
    } else {
        Each line of content = content.split('\n');
    }

    let output content = "";
    for (let x of each line) {
        if (x.includes('= tro' + 'jan,')) {
            const host = x.split("sni=")[1].split(",")[0];
            const backup_content = `sni=${host}, skip-cert-verify=${config_JSON.skip_cert_verify}`;
            const correct content = `sni=${host}, skip-cert-verify=${config_JSON.skip certificate verification}, ws=true, ws-path=${config_JSON.PATH}, ws-headers=Host:"${host}"`;
            Output content += x.replace(new RegExp("modified content, 'g'), correct content).replace("[", "").replace("]", "") + '\n';
        } else {
            Output content += x + '\n';
        }
    }

    Output content = `#!MANAGED-CONFIG ${url} interval=${config_JSON.preferred_subscription_generation.SUBUpdateTime * 60 * 60} strict=false` + Output content.substring(output content.indexOf('\n'));
    return the output content;
}
The async function requests logging (env, request, accessing IP, request type = "Get_SUB", config_JSON) {
    const KV capacity limit = 4; // MB
    try {
        const current time = new Date();
        `const log content = { TYPE: Request type, IP: Accessing IP, ASN: `AS${request.cf.asn || '0'} ${request.cf.asOrganization || 'Unknown'}`, CC: `${request.cf.country || 'N/A'} ${request.cf.city || 'N/A'}`, URL: request.url, UA: request.headers.get('User-Agent') || 'Unknown', TIME: Current time.getTime() };`
        let log array = [];
        const existing log = await env.KV.get('log.json');
        if (existing log) {
            try {
                log array = JSON.parse(existing log);
                if (!Array.isArray(log array)) { log array = [log content]; }
                else if (request type !== "Get_SUB") {
                    const timestamp of 30 minutes ago = current time.getTime() - 30 * 60 * 1000;
                    if (log array.some(log => log.TYPE !== "Get_SUB" && log.IP === accessing IP && log.URL === request.url && log.UA === (request.headers.get('User-Agent') || 'Unknown') && log.TIME >= timestamp from 30 minutes ago)) return;
                    log array.push(log content);
                    while (JSON.stringify(log array, null, 2).length > KV capacity limit * 1024 * 1024 && log array.length > 0) log array.shift();
                } else {
                    log array.push(log content);
                    while (JSON.stringify(log array, null, 2).length > KV capacity limit * 1024 * 1024 && log array.length > 0) log array.shift();
                }
                if (config_JSON.TG.Enable) {
                    try {
                        const TG_TXT = await env.KV.get('tg.json');
                        const TG_JSON = JSON.parse(TG_TXT);
                        await sendMessage(TG_JSON.BotToken, TG_JSON.ChatID, log content, config_JSON);
                    } catch (error) { console.error(`Error reading tg.json: ${error.message}`) }
                }
            } catch (e) { log array = [log content]; }
        } else { log array = [log content]; }
        await env.KV.put('log.json', JSON.stringify(log array, null, 2));
    } catch (error) { console.error(`Logging failed: ${error.message}`); }
}

The async function `sendMessage(BotToken, ChatID, log content, config_JSON)` {
    if (!BotToken || !ChatID) return;

    try {
        const request time = new Date(log content.TIME).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
        const requestURL = new URL(log content.URL);
        const msg = `<b>#${config_JSON.preferred_subscription_generation.SUBNAME} log_notification</b>\n\n` +
            `📌 <b>Type:</b>#${log content.TYPE}\n` +
            `🌐 <b>IP：</b><code>${log content.IP}</code>\n` +
            `📍 <b>Location:</b>${log content.CC}\n` +
            `🏢 <b>ASN：</b>${log content.ASN}\n` +
            `🔗 <b>Domain:</b><code>${request URL.host}</code>\n` +
            `🔍 <b>Path:</b><code>${request URL.pathname + request URL.search}</code>\n` +
            `🤖 <b>UA：</b><code>${log content.UA}</code>\n` +
            `📅 <b>Time:</b>${Requested Time}\n` +
            `${config_JSON.CF.Usage.success ? `📊 <b>Request usage:</b>${config_JSON.CF.Usage.total}/100000 <b>${((config_JSON.CF.Usage.total / 100000) * 100).toFixed(2)}%</b>\n` : ''}`;

        const url = `https://api.telegram.org/bot${BotToken}/sendMessage?chat_id=${ChatID}&parse_mode=HTML&text=${encodeURIComponent(msg)}`;
        return fetch(url, {
            method: 'GET',
            headers: {
                'Accept': 'text/html,application/xhtml+xml,application/xml;',
                'Accept-Encoding': 'gzip, deflate, br',
                'User-Agent': Log content.UA || 'Unknown'
            }
        });
    } catch (error) { console.error('Error sending message:', error) }
}

function mask_sensitive_information(text, prefix_length=3, suffix_length=2) {
    if (!text || typeof text !== 'string') return text;
    if (text.length <= prefix length + suffix length) return text; // If the length is too short, return the original text.

    const prefix = text.slice(0, prefix length);
    const suffix = text.slice(-suffix length);
    const asterisk count = text.length - prefix length - suffix length;

    return `${prefix}${'*'.repeat(number of asterisks)}${suffix}`;
}

async function MD5MD5(text) {
    const encoder = new TextEncoder();

    const first hash = await crypto.subtle.digest('MD5', encoder.encode(text));
    const first hash array = Array.from(new Uint8Array(first hash));
    const first hexadecimal = first hash array.map(byte=> byte.toString(16).padStart(2, '0')).join('');

    const second hash = await crypto.subtle.digest('MD5', encoder.encode(first hexadecimal.slice(7, 27)));
    const second hash array = Array.from(new Uint8Array(second hash));
    const second hexadecimal = second hash array.map(byte=> byte.toString(16).padStart(2, '0')).join('');

    return 2nd hexadecimal.toLowerCase();
}

function random path() {
    const common path directory= ["#","about","account","acg","act","activity","ad","admin","ads","ajax","album","albums","anime","api","app","apps","archive","archives","article","articles","ask","a uth","avatar","bbs","bd","blog","blogs","book","books","bt","buy","cart","category","categories","cb","channel","channels","chat","china","city","class","classify","cl ip","clips","club","cn","code","collect","collection","comic","comics","community","company","config","contact","content","course","courses","cp","data","detail","deta ils","dh","directory","discount","discuss","dl","dload","doc","docs","document","documents","doujin","download","downloads","drama","edu","en","ep","episode","episodes ","event","events","f","faq","favorite","favorites","favs","feedback","file","files","film","films","forum","forums","friend","friends","game","games","gif","go","go .html","go.php","group","groups","help","home","hot","htm","html","image","images","img","index","info","intro","item","items","ja","jp","jump","jump.html","jump.php", "jumping","knowledge","lang","lesson","lessons","lib","library","link","links","list","live","lives","login","logout","m","mag","magnet","mall","manhua","map","member" ,"members","message","messages","mobile","movie","movies","music","my","new","news","note","novel","novels","online","order","out","out.html","out.php","outbound","p","page","pages","pay","payment","pdf","photo","photos","pic","pics","picture","pictures","play","player","playlis t","post","posts","product","products","program","programs","project","qa","question","rank","ranking","read","r eadme","redirect","redirect.html","redirect.php","reg","register","res","resource","retrieve","sale","search","season","seasons","section","seller","series","service","services","setting","settings","share","shop","show","sh ows","site","soft","sort","source","special","star","stars","static","stock","store","stream","streaming","strea ms","student","study","tag","tags","task","teacher","team","tech","temp","test","thread","tool","tools","topic", "topics","torrent","trade","travel","tv","txt","type","u","upload","uploads","url","urls","user","users","v","ve rsion","video","videos","view","vip","vod","watch","web","wenku","wiki","work","www","zh","zh-cn","zh-tw","zip"];"special","star","stars","static","stock","store","stream","streaming","streams","student","study","tag","tags","task","teacher","team","tech","temp","test","thread","tool","tools","topic","topics","torrent" ,"trade","travel","tv","txt","type","u","upload","uploads","url","urls","user","users","v","version","v ideo","videos","view","vip","vod","watch","web","wenku","wiki","work","www","zh","zh-cn","zh-tw","zip"];"special","star","stars","static","stock","store","stream","streaming","streams","student","study","tag","tags","task","teacher","team","tech","temp","test","thread","tool","tools","topic","topics","torrent" ,"trade","travel","tv","txt","type","u","upload","uploads","url","urls","user","users","v","version","v ideo","videos","view","vip","vod","watch","web","wenku","wiki","work","www","zh","zh-cn","zh-tw","zip"];
    const random number = Math.floor(Math.random() * 3 + 1);
    const random path = common path directory.sort(() => 0.5 - Math.random()).slice(0, random number).join('/');
    return `/${random path}`;
}

function Randomly replace wildcard(h) {
    if (!h?.includes('*')) return h;
    const character set = 'abcdefghijklmnopqrstuvwxyz0123456789';
    return h.replace(/\*/g, () => {
        let s = '';
        for (let i = 0; i < Math.floor(Math.random() * 14) + 3; i++)
            s += character set[Math.floor(Math.random() * 36)];
        return s;
    });
}

function Batch replace domains(content, host, quantity per group = 2) {
    let count = 0, currentRandomHost = null;
    return content.replace(/example\.com/g, () => {
        If (count % number of groups === 0) currentRandomHost = random wildcard replacement(host);
        count++;
        return currentRandomHost;
    });
}

The async function reads config_JSON(env, hostname, userID, reset configuration = false) {
    const host = random wildcard replacement(hostname);
    const initialization start time = performance.now();
    const default configuration JSON = {
        TIME: new Date().toISOString(),
        HOST: host,
        UUID: userID,
        Protocol type: "v" + "le" + "ss",
        Transmission protocol: "ws",
        Skip certificate verification: true
        Enable 0RTT: true,
        TLS fragmentation: null,
        Random path: false,
        Preferred subscription generation: {
            local: true, // true: Preferred address based on local location; false: Preferred subscription generator.
            Local IP database: {
                Random IP: true, // This setting enables the number of random IPs; otherwise, it uses the ADD.txt file within the key-value store.
                Random number: 16
                Specify port: -1,
            },
            SUB: null,
            SUBNAME: "edge" + "tunnel",
            SUBUpdateTime: 6, // Subscription update time (hours)
            TOKEN: await MD5MD5(hostname + userID),
        },
        Subscription conversion configuration: {
            SUBAPI: "https://SUBAPI.cmliussss.net",
            SUBCONFIG: "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/refs/heads/master/Clash/config/ACL4SSR_Online_Mini_MultiMode.ini",
            SUBEMOJI: false,
        },
        Anti-substitution: {
            PROXYIP: "auto",
            SOCKS5: {
                Enable: Enable SOCKS5 reverse proxy.
                Global: Enable SOCKS5 global reverse proxy.
                Account: My SOCKS5 account
                Whitelist: SOCKS5 whitelist
            },
        },
        TG: {
            Enable: false,
            BotToken: null,
            ChatID: null,
        },
        CF: {
            Email: null,
            GlobalAPIKey: null,
            AccountID: null,
            APIToken: null,
            Usage: {
                success: false,
                pages: 0,
                workers: 0,
                total: 0,
            },
        }
    };

    try {
        let configJSON = await env.KV.get('config.json');
        if (!configJSON || Reset Configuration == true) {
            await env.KV.put('config.json', JSON.stringify('default configuration JSON', null, 2));
            config_JSON = default configuration JSON;
        } else {
            config_JSON = JSON.parse(configJSON);
        }
    } catch (error) {
        console.error(`Error reading config_JSON: ${error.message}`);
        config_JSON = default configuration JSON;
    }

    config_JSON.HOST = host;
    config_JSON.UUID = userID;
    `config_JSON.PATH = config_JSON.reverse_proxy.SOCKS5.enabled?('/' + config_JSON.reverse_proxy.SOCKS5.enabled+(config_JSON.reverse_proxy.SOCKS5.global?'://':'=') + config_JSON.reverse_proxy.SOCKS5.account) :(config_JSON.reverse_proxy.PROXYIP === 'auto'?'/': `/proxyip=${config_JSON.reverse_proxy.PROXYIP}`);`
    const TLS fragmentation parameter = config_JSON.TLS fragment == 'Shadowrocket' ? `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}` : config_JSON.TLS fragment == 'Happ' ? `&fragment=${encodeURIComponent('3,1,tlshello')}` : '';
    `config_JSON.LINK = `${config_JSON.protocol_type}://${userID}@${host}:443?security=tls&type=${config_JSON.transport_protocol}&host=${host}&sni=${host}&path=${encodeURIComponent(config_JSON.enable_0RTT? config_JSON.PATH + '?ed=2560' : config_JSON.PATH) + TLS_fragmentation_parameters}&encryption=none${config_JSON.skip_certificate_verification? '&allowInsecure=1' : ''}#${encodeURIComponent(config_JSON.preferred_subscription_generator.SUBNAME)}`;`
    config_JSON.preferred_subscription_generation.TOKEN = await MD5MD5(hostname + userID);

    const initializes TG_JSON = { BotToken: null, ChatID: null };
    config_JSON.TG = { Enable: config_JSON.TG.Enable? config_JSON.TG.Enable: false, ...Initialize TG_JSON };
    try {
        const TG_TXT = await env.KV.get('tg.json');
        if (!TG_TXT) {
            await env.KV.put('tg.json', JSON.stringify(initialize TG_JSON, null, 2));
        } else {
            const TG_JSON = JSON.parse(TG_TXT);
            config_JSON.TG.ChatID = TG_JSON.ChatID ? TG_JSON.ChatID : null;
            config_JSON.TG.BotToken = TG_JSON.BotToken ? Mask Sensitive Information(TG_JSON.BotToken) : null;
        }
    } catch (error) {
        console.error(`Error reading tg.json: ${error.message}`);
    }

    The `CF_JSON` function is initialized as follows: `const CF_JSON = { Email: null, GlobalAPIKey: null, AccountID: null, APIToken: null };`
    config_JSON.CF = { ...initialize CF_JSON, Usage: { success: false, pages: 0, workers: 0, total: 0 } };
    try {
        const CF_TXT = await env.KV.get('cf.json');
        if (!CF_TXT) {
            await env.KV.put('cf.json', JSON.stringify(initialize CF_JSON, null, 2));
        } else {
            const CF_JSON = JSON.parse(CF_TXT);
            config_JSON.CF.Email = CF_JSON.Email ? CF_JSON.Email : null;
            config_JSON.CF.GlobalAPIKey = CF_JSON.GlobalAPIKey ? Mask Sensitive Information(CF_JSON.GlobalAPIKey) : null;
            config_JSON.CF.AccountID = CF_JSON.AccountID ? Mask Sensitive Information(CF_JSON.AccountID) : null;
            config_JSON.CF.APIToken = CF_JSON.APIToken ? Mask Sensitive Information(CF_JSON.APIToken) : null;
            const Usage = await getCloudflareUsage(CF_JSON.Email, CF_JSON.GlobalAPIKey, CF_JSON.AccountID, CF_JSON.APIToken);
            config_JSON.CF.Usage = Usage;
        }
    } catch (error) {
        console.error(`Error reading cf.json: ${error.message}`);
    }

    config_JSON.load time = (performance.now() - initialization start time).toFixed(2) + 'ms';
    return config_JSON;
}

The async function generates a random IP address (request, count = 16, specified port = -1) {
    const asnMap = { '9808': 'cmcc', '4837': 'cu', '4134': 'ct' }, asn = request.cf.asn;
    const cidr_url = asnMap[asn] ? `https://raw.githubusercontent.com/cmliu/cmliu/main/CF-CIDR/${asnMap[asn]}.txt` : 'https://raw.githubusercontent.com/cmliu/cmliu/main/CF-CIDR.txt';
    const cfname = { '9808': 'CF Mobile Preferred', '4837': 'CF Unicom Preferred', '4134': 'CF Telecom Preferred' }[asn] || 'CF Official Preferred';
    const cfport = [443, 2053, 2083, 2087, 2096, 8443];
    let cidrList = [];
    try { const res = await fetch(cidr_url); cidrList = res.ok ? await res.text() : ['104.16.0.0/13']; } catch { cidrList = ['104.16.0.0/13']; }

    const generateRandomIPFromCIDR = (cidr) => {
        const [baseIP, prefixLength] = cidr.split('/'), prefix = parseInt(prefixLength), hostBits = 32 - prefix;
        const ipInt = baseIP.split('.').reduce((a, p, i) => a | (parseInt(p) << (24 - i * 8)), 0);
        const randomOffset = Math.floor(Math.random() * Math.pow(2, hostBits));
        const mask = (0xFFFFFFFF << hostBits) >>> 0, randomIP = (((ipInt & mask) >>> 0) + randomOffset) >>> 0;
        return [(randomIP >>> 24) & 0xFF, (randomIP >>> 16) & 0xFF, (randomIP >>> 8) & 0xFF, randomIP & 0xFF].join('.');
    };

    const randomIPs = Array.from({ length: count }, () => {
        const ip = generateRandomIPFromCIDR(cidrList[Math.floor(Math.random() * cidrList.length)]);
        return `${ip}:${specified port=== -1 ? cfport[Math.floor(Math.random() * cfport.length)] : specified port}#${cfname}`;
    });
    return [randomIPs, randomIPs.join('\n')];
}
The async function organizes the data into an array (contents) {
    The code snippet `var replaced content = content.replace(/[ "'\r\n]+/g, ',').replace(/,+/g, ',');` is used to replace the content of the replacement.
    If (replaced content.charAt(0) == ',') replaced content = replaced content.slice(1);
    If `replaced content.charAt(replaced content.length - 1) == ','`, then `replaced content = replaced content.slice(0, replaced content.length - 1);`
    const address array = replaced content.split(',');
    return the array of addresses;
}

The async function requests the preferred API (urls, default port = '443', timeout = 3000) {
    if (!urls?.length) return [];
    const results = new Set();
    await Promise.allSettled(urls.map(async (url) => {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), timeout period);
            const response = await fetch(url, { signal: controller.signal });
            clearTimeout(timeoutId);
            let text = '';
            try {
                const buffer = await response.arrayBuffer();
                const contentType = (response.headers.get('content-type') || '').toLowerCase();
                const charset = contentType.match(/charset=([^\s;]+)/i)?.[1]?.toLowerCase() || '';

                // Determine encoding priority based on the Content-Type response header
                let decoders = ['utf-8', 'gb2312']; // UTF-8 is preferred by default
                if (charset.includes('gb') || charset.includes('gbk') || charset.includes('gb2312')) {
                    decoders = ['gb2312', 'utf-8']; // If GB encoding is explicitly specified, GB2312 will be tried first.
                }

                // Try multiple encoding and decoding methods
                let decodeSuccess = false;
                for (const decoder of decoders) {
                    try {
                        const decoded = new TextDecoder(decoder).decode(buffer);
                        // Verify the validity of the decoding result
                        if (decoded && decoded.length > 0 && !decoded.includes('\ufffd')) {
                            text = decoded;
                            decodeSuccess = true;
                            break
                        } else if (decoded && decoded.length > 0) {
                            // If a replacement character (U+FFFD) is found, it means the encoding does not match; continue trying the next encoding.
                            continue?
                        }
                    } catch (e) {
                        // This encoding/decoding failed, try the next one.
                        continue?
                    }
                }

                // If all encodings fail or are invalid, try response.text()
                if (!decodeSuccess) {
                    text = await response.text();
                }

                // If the returned value is empty or invalid, return 0.
                if (!text || text.trim().length === 0) {
                    return;
                }
            } catch (e) {
                console.error('Failed to decode response:', e);
                return;
            }
            const lines = text.trim().split('\n').map(l => l.trim()).filter(l => l);
            const isCSV = lines.length > 1 && lines[0].includes(',');
            const IPV6_PATTERN = /^[^\[\]]*:[^\[\]]*:[^\[\]]/;
            if (!isCSV) {
                lines.forEach(line => {
                    const hashIndex = line.indexOf('#');
                    const [hostPart, remark] = hashIndex > -1 ? [line.substring(0, hashIndex), line.substring(hashIndex)] : [line, ''];
                    let hasPort = false;
                    if (hostPart.startsWith('[')) {
                        hasPort = /\]:(\d+)$/.test(hostPart);
                    } else {
                        const colonIndex = hostPart.lastIndexOf(':');
                        hasPort = colonIndex > -1 && /^\d+$/.test(hostPart.substring(colonIndex + 1));
                    }
                    const port = new URL(url).searchParams.get('port') || Default port;
                    results.add(hasPort ? line : `${hostPart}:${port}${remark}`);
                });
            } else {
                const headers = lines[0].split(',').map(h => h.trim());
                const dataLines = lines.slice(1);
                if (headers.includes('IP address') && headers.includes('port') && headers.includes('data center')) {
                    const ipIdx = headers.indexOf('IP address'), portIdx = headers.indexOf('port');
                    const remarkIdx = headers.indexOf('country') > -1 ? headers.indexOf('country') :
                        `headers.indexOf('City') > -1 ? headers.indexOf('City') : headers.indexOf('Data Center');`
                    dataLines.forEach(line => {
                        const cols = line.split(',').map(c => c.trim());
                        const wrappedIP = IPV6_PATTERN.test(cols[ipIdx]) ? `[${cols[ipIdx]}]` : cols[ipIdx];
                        results.add(`${wrappedIP}:${cols[portIdx]}#${cols[remarkIdx]}`);
                    });
                } else if (headers.some(h => h.includes('IP')) && headers.some(h => h.includes('Delay')) && headers.some(h => h.includes('Download Speed'))) {
                    const ipIdx = headers.findIndex(h => h.includes('IP'));
                    const delayIdx = headers.findIndex(h => h.includes('delay'));
                    const speedIdx = headers.findIndex(h => h.includes('download speed'));
                    const port = new URL(url).searchParams.get('port') || Default port;
                    dataLines.forEach(line => {
                        const cols = line.split(',').map(c => c.trim());
                        const wrappedIP = IPV6_PATTERN.test(cols[ipIdx]) ? `[${cols[ipIdx]}]` : cols[ipIdx];
                        results.add(`${wrappedIP}:${port}#CF preferred ${cols[delayIdx]}ms ${cols[speedIdx]}MB/s`);
                    });
                }
            }
        } catch (e) { }
    }));
    return Array.from(results);
}

async function reverse proxy parameter retrieval (request) {
    const url = new URL(request.url);
    const { pathname, searchParams } = url;
    const pathLower = pathname.toLowerCase();

    // Initialization
    My SOCKS5 account = searchParams.get('socks5') || searchParams.get('http') || null;
    Enable SOCKS5 global reverse proxy = searchParams.has('globalproxy') || false;

    // Process reverse proxy IP parameters uniformly (highest priority, use regular expressions for one-time matching)
    const proxyMatch = pathLower.match(/\/(proxyip[.=]|pyip=|ip=)(.+)/);
    if (searchParams.has('proxyip')) {
        const road parameter IP = searchParams.get('proxyip');
        The reverse proxy IP is defined as follows: `IP.includes(',') ? IP.split(',')[Math.floor(Math.random() * IP.split(',').length)] : IP;`
        return;
    } else if (proxyMatch) {
        const path parameter IP = proxyMatch[1] === 'proxyip.' ? `proxyip.${proxyMatch[2]}` : proxyMatch[2];
        The reverse proxy IP is defined as follows: `IP.includes(',') ? IP.split(',')[Math.floor(Math.random() * IP.split(',').length)] : IP;`
        return;
    }

    // Handling SOCKS5/HTTP proxy parameters
    Let socksMatch;
    if ((socksMatch = pathname.match(/\/(socks5?|http):\/?\/?(.+)/i))) {
        // Format: /socks5://... or /http://...
        Enable SOCKS5 reverse proxy = socksMatch[1].toLowerCase() === 'http' ? 'http' : 'socks5';
        My SOCKS5 account = socksMatch[2].split('#')[0];
        Enable SOCKS5 global reverse proxy = true;

        // Process Base64 encoded usernames and passwords
        if (my SOCKS5 account.includes('@')) {
            const atIndex = my SOCKS5 account.lastIndexOf('@');
            let userPassword = "My SOCKS5 account".substring(0, atIndex).replaceAll('%3D', '=');
            if (/^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i.test(userPassword) && !userPassword.includes(':')) {
                userPassword = atob(userPassword);
            }
            My SOCKS5 account = `${userPassword}@${mySOCKS5 account.substring(atIndex + 1)}`;
        }
    } else if ((socksMatch = pathname.match(/\/(g?s5|socks5|g?http)=(.+)/i))) {
        // Format: /socks5=... or /s5=... or /gs5=... or /http=... or /ghttp=...
        const type = socksMatch[1].toLowerCase();
        My SOCKS5 account = socksMatch[2];
        Enable SOCKS5 reverse proxy = type.includes('http') ? 'http' : 'socks5';
        Enable SOCKS5 global reverse proxy = type.startsWith('g') || Enable SOCKS5 global reverse proxy; // Enables global proxy if starting with gs5 or ghttp
    }

    // Resolving SOCKS5 addresses
    if (my SOCKS5 account) {
        try {
            `parsedSocks5Address = await` retrieves the SOCKS5 account (my SOCKS5 account);
            Enable SOCKS5 reverse proxy = searchParams.get('http') ? 'http' : Enable SOCKS5 reverse proxy;
        } catch (err) {
            console.error('Failed to resolve SOCKS5 address:', err.message);
            Enable SOCKS5 reverse proxy = null;
        }
    else Enable SOCKS5 reverse proxy = null;
}

an async function retrieves the SOCKS5 account (address) {
    if (address.includes('@')) {
        const lastAtIndex = address.lastIndexOf('@');
        let userPassword = address.substring(0, lastAtIndex).replaceAll('%3D', '=');
        const base64Regex = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;
        if (base64Regex.test(userPassword) && !userPassword.includes(':')) userPassword = atob(userPassword);
        address = `${userPassword}@${address.substring(lastAtIndex + 1)}`;
    }
    const atIndex = address.lastIndexOf("@");
    const [hostPart, authPart] = atIndex === -1 ? [address, undefined] : [address.substring(atIndex + 1), address.substring(0, atIndex)];

    // Parse authentication
    let username, password;
    if (authPart) {
        [username, password] = authPart.split(":");
        if (!password) throw new Error('Invalid SOCKS address format: the authentication part must be in the form "username:password"');
    }

    // Resolve host ports
    let hostname, port;
    if (hostPart.includes("]:")) { // IPv6 with port
        [hostname, port] = [hostPart.split("]:")[0] + "]", Number(hostPart.split("]:")[1].replace(/[^\d]/g, ''))];
    } else if (hostPart.startsWith("[")) { // IPv6 without port
        [hostname, port] = [hostPart, 80];
    } else { // IPv4/domain
        const parts = hostPart.split(":");
        [hostname, port] = parts.length === 2 ? [parts[0], Number(parts[1].replace(/[^\d]/g, ''))] : [hostPart, 80];
    }

    if (isNaN(port)) throw new Error('Invalid SOCKS address format: port number must be a number');
    if (hostname.includes(":") && !/^\[.*\]$/.test(hostname)) throw new Error('Invalid SOCKS address format: IPv6 addresses must be enclosed in square brackets, such as [2001:db8::1]');

    return { username, password, hostname, port };
}

async function getCloudflareUsage(Email, GlobalAPIKey, AccountID, APIToken) {
    const API = "https://api.cloudflare.com/client/v4";
    const sum = (a) => a?.reduce((t, i) => t + (i?.sum?.requests || 0), 0) || 0;
    const cfg = { "Content-Type": "application/json" };

    try {
        if (!AccountID && (!Email || !GlobalAPIKey)) return { success: false, pages: 0, workers: 0, total: 0 };

        if (!AccountID) {
            const r = await fetch(`${API}/accounts`, {
                method: "GET"
                headers: { ...cfg, "X-AUTH-EMAIL": Email, "X-AUTH-KEY": GlobalAPIKey }
            });
            If (!r.ok) throws a new Error(`Account retrieval failed: ${r.status}`);
            const d = await r.json();
            If (!d?.result?.length) throws a new Error("Account not found");
            const idx = d.result.findIndex(a => a.name?.toLowerCase().startsWith(Email.toLowerCase()));
            AccountID = d.result[idx >= 0 ? idx : 0]?.id;
        }

        const now = new Date();
        now.setUTCHours(0, 0, 0, 0);
        const hdr = APIToken ? { ...cfg, "Authorization": `Bearer ${APIToken}` } : { ...cfg, "X-AUTH-EMAIL": Email, "X-AUTH-KEY": GlobalAPIKey };

        const res = await fetch(`${API}/graphql`, {
            method: "POST"
            headers: hdr,
            body: JSON.stringify({
                query: `query getBillingMetrics($AccountID: String!, $filter: AccountWorkersInvocationsAdaptiveFilter_InputObject) {
                    viewer { accounts(filter: {accountTag: $AccountID}) {
                        pagesFunctionsInvocationsAdaptiveGroups(limit: 1000, filter: $filter) { sum { requests } }
                        workersInvocationsAdaptive(limit: 10000, filter: $filter) { sum { requests } }
                    } }
                }`,
                variables: { AccountID, filter: { datetime_geq: now.toISOString(), datetime_leq: new Date().toISOString() } }
            })
        });

        If (!res.ok) throws a new Error(`Query failed: ${res.status}`);
        const result = await res.json();
        if (result.errors?.length) throw new Error(result.errors[0].message);

        const acc = result?.data?.viewer?.accounts?.[0];
        if (!acc) throw new Error("Account data not found");

        const pages = sum(acc.pagesFunctionsInvocationsAdaptiveGroups);
        const workers = sum(acc.workersInvocationsAdaptive);
        const total = pages + workers;
        console.log(`Statistics - Pages: ${pages}, Workers: ${workers}, Total: ${total}`);
        return { success: true, pages, workers, total };

    } catch (error) {
        console.error('Error retrieving usage:', error.message);
        return { success: false, pages: 0, workers: 0, total: 0 };
    }
}

function sha224(s) {
    const K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
    const r = (n, b) => ((n >>> b) | (n << (32 - b))) >>> 0;
    s = unescape(encodeURIComponent(s));
    const l = s.length * 8; s += String.fromCharCode(0x80);
    while ((s.length * 8) % 512 !== 448) s += String.fromCharCode(0);
    const h = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
    const hi = Math.floor(l / 0x100000000), lo = l & 0xFFFFFFFF;
    s += String.fromCharCode((hi >>> 24) & 0xFF, (hi >>> 16) & 0xFF, (hi >>> 8) & 0xFF, hi & 0xFF, (lo >>> 24) & 0xFF, (lo >>> 16) & 0xFF, (lo >>> 8) & 0xFF, lo & 0xFF);
    const w = []; for (let i = 0; i < s.length; i += 4)w.push((s.charCodeAt(i) << 24) | (s.charCodeAt(i + 1) << 16) | (s.charCodeAt(i + 2) << 8) | s.charCodeAt(i + 3));
    for (let i = 0; i < w.length; i += 16) {
        const x = new Array(64).fill(0);
        for (let j = 0; j < 16; j++)x[j] = w[i + j];
        for (let j = 16; j < 64; j++) {
            const s0 = r(x[j - 15], 7) ^ r(x[j - 15], 18) ^ (x[j - 15] >>> 3);
            const s1 = r(x[j - 2], 17) ^ r(x[j - 2], 19) ^ (x[j - 2] >>> 10);
            x[j] = (x[j - 16] + s0 + x[j - 7] + s1) >>> 0;
        }
        let [a, b, c, d, e, f, g, h0] = h;
        for (let j = 0; j < 64; j++) {
            const S1 = r(e, 6) ^ r(e, 11) ^ r(e, 25), ch = (e & f) ^ (~e & g), t1 = (h0 + S1 + ch + K[j] + x[j]) >>> 0;
            const S0 = r(a, 2) ^ r(a, 13) ^ r(a, 22), maj = (a & b) ^ (a & c) ^ (b & c), t2 = (S0 + maj) >>> 0;
            h0 = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
        }
        for (let j = 0; j < 8; j++)h[j] = (h[j] + (j === 0 ? a : j === 1 ? b : j === 2 ? c : j === 3 ? d : j === 4 ? e : j === 5 ? f : j === 6 ? g : h0)) >>> 0;
    }
    let hex = '';
    for (let i = 0; i < 7; i++) {
        for (let j = 24; j >= 0; j -= 8)hex += ((h[i] >>> j) & 0xFF).toString(16).padStart(2, '0');
    }
    return hex;
}

async function resolves address and port (proxyIP) {
    proxyIP = proxyIP.toLowerCase();
    if (proxyIP.includes('.william')) {
        const williamResult = await (async function resolveWilliamdomain(william) {
            try {
                const response = await fetch(`https://1.1.1.1/dns-query?name=${william}&type=TXT`, { headers: { 'Accept': 'application/dns-json' } });
                if (!response.ok) return null;
                const data = await response.json();
                const txtRecords = (data.Answer || []).filter(record => record.type === 16).map(record => record.data);
                if (txtRecords.length === 0) return null;
                let txtData = txtRecords[0];
                if (txtData.startsWith('"') && txtData.endsWith('"')) txtData = txtData.slice(1, -1);
                const prefixes = txtData.replace(/\\010/g, ',').replace(/\n/g, ',').split(',').map(s => s.trim()).filter(Boolean);
                if (prefixes.length === 0) return null;
                return prefixes[Math.floor(Math.random() * prefixes.length)];
            } catch (error) {
                console.error('Failed to resolve ProxyIP:', error);
                return null;
            }
        })(proxyIP);
        proxyIP = williamResult || proxyIP;
    }
    let address=proxyIP, port=443;
    if (proxyIP.includes('.tp')) {
        const tpMatch = proxyIP.match(/\.tp(\d+)/);
        if (tpMatch) port = parseInt(tpMatch[1], 10);
        return [address, port];
    }
    if (proxyIP.includes(']:')) {
        const parts = proxyIP.split(']:');
        Address = parts[0] + ']';
        port = parseInt(parts[1], 10) || port;
    } else if (proxyIP.includes(':') && !proxyIP.startsWith('[')) {
        const colonIndex = proxyIP.lastIndexOf(':');
        address = proxyIP.slice(0, colonIndex);
        port = parseInt(proxyIP.slice(colonIndex + 1), 10) || port;
    }
    return [address, port];
}

async function SOCKS5 availability verification(proxy protocol='socks5', proxy parameters) {
    const startTime = Date.now();
    try { parsedSocks5Address = await 'Get SOCKS5 account(proxy parameter); } catch (err) { return { success: false, error: err.message, proxy: proxy protocol + "://" + proxy parameter, responseTime: Date.now() - startTime }; }
    const { username, password, hostname, port } = parsedSocks5Address;
    const Full proxy parameters = username && password ? `${username}:${password}@${hostname}:${port}` : `${hostname}:${port}`;
    try {
        const initialData = new Uint8Array(0);
        const tcpSocket = proxy protocol == 'socks5' ? await socks5Connect('check.socks5.090227.xyz', 80, initialData) : await httpConnect('check.socks5.090227.xyz', 80, initialData);
        If (!tcpSocket) return { success: false, error: 'Unable to connect to proxy server', proxy: proxy protocol + "://" + full proxy parameters, responseTime: Date.now() - startTime };
        try {
            const writer = tcpSocket.writable.getWriter(), encoder = new TextEncoder();
            await writer.write(encoder.encode(`GET /cdn-cgi/trace HTTP/1.1\r\nHost: check.socks5.090227.xyz\r\nConnection: close\r\n\r\n`));
            writer.releaseLock();
            const reader = tcpSocket.readable.getReader(), decoder = new TextDecoder();
            let response = '';
            try { while (true) { const { done, value } = await reader.read(); if (done) break; response += decoder.decode(value, { stream: true }); } } finally { reader.releaseLock(); }
            await tcpSocket.close();
            return { success: true, proxy: proxy protocol + "://" + complete proxy parameters, ip: response.match(/ip=(.*)/)[1], loc: response.match(/loc=(.*)/)[1], responseTime: Date.now() - startTime };
        } catch (error) {
            try { await tcpSocket.close(); } catch (e) { console.log('Error closing connection:', e); }
            return { success: false, error: error.message, proxy: proxy protocol + "://" + complete proxy parameters, responseTime: Date.now() - startTime };
        }
    } catch (error) { return { success: false, error: error.message, proxy: proxy protocol + "://" + complete proxy parameters, responseTime: Date.now() - startTime }; }
}
///////////////////////////////////////////////////////HTML Disguised Page/////////////////////////////////////////////////////////
async function nginx() {
    return `
	<!DOCTYPE html>
	<html>
	<head>
	<title>Welcome to nginx!</title>
	<style>
		body {
			width: 35em;
			margin: 0 auto;
			font-family: Tahoma, Verdana, Arial, sans-serif;
		}
	</style>
	</head>
	<body>
	<h1>Welcome to nginx!</h1>
	<p>If you see this page, the nginx web server is successfully installed and
	working. Further configuration is required.</p>
	
	<p>For online documentation and support please refer to
	<a href="http://nginx.org/">nginx.org</a>.<br/>
	Commercial support is available at
	<a href="http://nginx.com/">nginx.com</a>.</p>
	
	<p><em>Thank you for using nginx.</em></p>
	</body>
	</html>
	`
}

async function html1101(host, access IP) {
    const now = new Date();
    const formatted timestamp = now.getFullYear() + '-' + String(now.getMonth() + 1).padStart(2, '0') + '-' + String(now.getDate()).padStart(2, '0') + ' ' + String(now.getHours()).padStart(2, '0') + ':' + String(now.getMinutes()).padStart(2, '0') + ':' + String(now.getSeconds()).padStart(2, '0');
    const random string = Array.from(crypto.getRandomValues(new Uint8Array(8))).map(b => b.toString(16).padStart(2, '0')).join('');

    return `<!DOCTYPE html>
<!--[if lt IE 7]> <html class="no-js ie6 oldie" lang="en-US"> <![endif]-->
<!--[if IE 7]> <html class="no-js ie7 oldie" lang="en-US"> <![endif]-->
<!--[if IE 8]> <html class="no-js ie8 oldie" lang="en-US"> <![endif]-->
<!--[if gt IE 8]><!--> <html class="no-js" lang="en-US"> <!--<![endif]-->
<head>
<title>Worker threw exception | ${host} | Cloudflare</title>
<meta charset="UTF-8" />
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<meta http-equiv="X-UA-Compatible" content="IE=Edge" />
<meta name="robots" content="noindex, nofollow" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<link rel="stylesheet" id="cf_styles-css" href="/cdn-cgi/styles/cf.errors.css" />
<!--[if lt IE 9]><link rel="stylesheet" id='cf_styles-ie-css' href="/cdn-cgi/styles/cf.errors.ie.css" /><![endif]-->
<style>body{margin:0;padding:0}</style>


<!--[if gte IE 10]><!-->
<script>
  if (!navigator.cookieEnabled) {
    window.addEventListener('DOMContentLoaded', function () {
      var cookieEl = document.getElementById('cookie-alert');
      cookieEl.style.display = 'block';
    })
  }
</script>
<!--<![endif]-->

</head>
<body>
    <div id="cf-wrapper">
        <div class="cf-alert cf-alert-error cf-cookie-error" id="cookie-alert" data-translate="enable_cookies">Please enable cookies.</div>
        <div id="cf-error-details" class="cf-error-details-wrapper">
            <div class="cf-wrapper cf-header cf-error-overview">
                <h1>
                    <span class="cf-error-type" data-translate="error">Error</span>
                    <span class="cf-error-code">1101</span>
                    Ray ID: ${random string} • ${formatted timestamp} UTC</small>
                </h1>
                <h2 class="cf-subheadline" data-translate="error_desc">Worker threw exception</h2>
            </div><!-- /.header -->
    
            <section></section><!-- spacer -->
    
            <div class="cf-section cf-wrapper">
                <div class="cf-columns two">
                    <div class="cf-column">
                        <h2 data-translate="what_happened">What happened?</h2>
                            <p>You've requested a page on a website (${host}) that is on the <a href="https://www.cloudflare.com/5xx-error-landing?utm_source=error_100x" target="_blank">Cloudflare</a> network. An unknown error occurred while rendering the page.</p>
                    </div>
                    
                    <div class="cf-column">
                        <h2 data-translate="what_can_i_do">What can I do?</h2>
                            <p><strong>If you are the owner of this website:</strong><br />refer to <a href="https://developers.cloudflare.com/workers/observability/errors/" target="_blank">Workers - Errors and Exceptions</a> and check Workers Logs for ${host}.</p>
                    </div>
                    
                </div>
            </div><!-- /.section -->
    
            <div class="cf-error-footer cf-wrapper w-240 lg:w-full py-10 sm:py-4 sm:px-8 mx-auto text-center sm:text-left border-solid border-0 border-t border-gray-300">
    <p class="text-13">
      Cloudflare Ray ID: ${random string}
      <span class="cf-footer-separator sm:hidden">•</span>
      <span id="cf-footer-item-ip" class="cf-footer-item hidden sm:block sm:mb-1">
        Your IP:
        <button type="button" id="cf-footer-ip-reveal" class="cf-footer-ip-reveal-btn">Click to reveal</button>
        <span class="hidden" id="cf-footer-ip">${Access IP}</span>
        <span class="cf-footer-separator sm:hidden">•</span>
      </span>
      <span class="cf-footer-item sm:block sm:mb-1"><span>Performance & security by</span> <a rel="noopener noreferrer" href="https://www.cloudflare.com/5xx-error-landing" id="brand_link" target="_blank">Cloudflare</a></span>
      
    </p>
    <script>(function(){function d(){var b=a.getElementById("cf-footer-item-ip"),c=a.getElementById("cf-footer-ip-reveal");b&&"classList"in b&&(b.classList.remove("hidden"),c.addEventListener("click",function(){c.classList.add("hidden");a.getElementById("cf-footer-ip").classList.remove("hidden")}))}var a=document;document.addEventListener&&a.addEventListener("DOMContentLoaded",d)})();</script>
  </div><!-- /.error-footer -->

        </div><!-- /#cf-error-details -->
    </div><!-- /#cf-wrapper -->

     <script>
    window._cf_translation = {};
    
    
  </script>
</body>
</html>`;
}
