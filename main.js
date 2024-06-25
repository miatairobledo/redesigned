import fetch, { Headers, Response } from 'node-fetch';
import faker from 'faker';
import http from 'http';
import { URL } from 'url';
import https from 'https';
import net from 'net';
import HttpsProxyAgent from 'https-proxy-agent';

const upstream_path = '';
const disable_cache = false;
const replace_dict = {
    '$upstream': '$custom_domain'
};

const proxy_host = process.env.PROXY_HOST || null;
const proxy_port = process.env.PROXY_PORT || null;
const proxy_auth = process.env.PROXY_AUTH || null;

// Función para deshabilitar la verificación de certificados SSL
function disableSSLVerification() {
    return new https.Agent({ rejectUnauthorized: false });
}

const agent = proxy_host && proxy_port ? new HttpsProxyAgent({
    host: proxy_host,
    port: proxy_port,
    auth: proxy_auth,
    rejectUnauthorized: false
}) : disableSSLVerification();

// Función para determinar y procesar automáticamente solicitudes HTTP y HTTPS, IPs y IPs con puerto, URLs y links
function processRequest(urlStr, method, headers, body) {
    let url;
    try {
        url = new URL(urlStr);
    } catch (error) {
        return new Response(`Invalid URL: ${urlStr}`, { status: 400 });
    }

    const protocol = url.protocol.toLowerCase();
    const isHttps = protocol === 'https:';
    const isHttp = protocol === 'http:';

    if (!isHttps && !isHttp) {
        return new Response(`Unsupported protocol: ${protocol}`, { status: 400 });
    }

    const requestOptions = {
        method: method,
        headers: headers,
        agent: isHttps ? agent : undefined
    };

    if (method !== 'GET' && method !== 'HEAD') {
        requestOptions.body = body;
    }

    return fetch(url.href, requestOptions);
}

async function replace_response_text(response, upstream_domain, host_name) {
    let text = await response.text();
    for (const i in replace_dict) {
        const j = replace_dict[i];
        const re = new RegExp(i, 'g');
        text = text.replace(re, i === '$upstream' ? upstream_domain : host_name);
    }
    return text;
}

function generateFakeIP() {
    return faker.internet.ipv4();  // Generate fake IPv4 address
}

function generateFakeUserAgent() {
    return faker.internet.userAgent();
}

function generateFakeGeolocation() {
    return `${faker.address.latitude()}, ${faker.address.longitude()}`;
}

function generateFakeTime() {
    return faker.date.recent().toISOString();
}

function modifyHeaders(headers, url) {
    headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
    headers.set('Pragma', 'no-cache');
    headers.set('Expires', '0');
    headers.set('DNT', '1');
    headers.set('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8');
    headers.set('Accept-Language', 'en-US,en;q=0.5');
    headers.set('Upgrade-Insecure-Requests', '1');

    headers.delete('g-recaptcha-response');
    headers.delete('google-captcha-response');
    headers.delete('google-site-verification');
    headers.delete('cf-ray');
    headers.delete('cf-request-id');
    headers.delete('h-captcha-response');
    headers.delete('x-captcha-id');
    headers.delete('x-captcha-token');

    headers.delete('x-instagram-ajax');
    headers.delete('x-requested-with');
    headers.delete('origin');
    headers.delete('x-csrftoken');
    headers.delete('x-ig-app-id');
    headers.delete('x-ig-www-claim');
    headers.delete('x-ig-origin-region');
    headers.delete('x-ig-connection-type');
    headers.delete('x-ig-capabilities');
    headers.delete('x-ig-app-module');
    headers.delete('x-fb-http-engine');
    headers.delete('x-fb-host');
    headers.delete('captcha-id');
    headers.delete('captcha-token');

    headers.delete('instagram-ajax');
    headers.delete('requested-with');
    headers.delete('origin');
    headers.delete('csrftoken');
    headers.delete('ig-app-id');
    headers.delete('ig-www-claim');
    headers.delete('ig-origin-region');
    headers.delete('ig-connection-type');
    headers.delete('ig-capabilities');
    headers.delete('ig-app-module');
    headers.delete('fb-http-engine');
    headers.delete('fb-host');

    headers.delete('Sec-Ch-Ua');
    headers.delete('Sec-Ch-Ua-Mobile');
    headers.delete('Sec-Ch-Ua-Platform');
    headers.delete('Sec-Fetch-Dest');
    headers.delete('Sec-Fetch-Mode');
    headers.delete('Sec-Fetch-Site');
    headers.delete('Sec-Fetch-User');
    headers.delete('Dpr');
    headers.delete('Viewport-Width');
    headers.delete('Downlink');
    headers.delete('Ect');
    headers.delete('Rtt');
    headers.delete('Accept-Encoding');
    headers.delete('X-Requested-With');
    headers.delete('X-Forwarded-For');
    headers.delete('Via');

    headers.set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36');
    headers.set('Referer', 'https://www.google.com/');
    headers.delete('Cookie');
    headers.delete('x-popups');
    headers.delete('x-ads');
    headers.delete('x-view-emergent');
    headers.delete('x-emergent-screen');
    headers.delete('x-ventanas-emergentes');
    headers.delete('x-vistas-emergentes');
    headers.delete('x-google-captcha-v1');
    headers.delete('x-google-captcha-v2');
    headers.delete('x-google-captcha-v3');
    headers.delete('x-bot-protection');
    headers.delete('x-spam-protection');
    headers.delete('x-views-protection');
    headers.delete('x-login');
    headers.delete('x-singing');
    headers.delete('x-registro');
    headers.delete('x-inicio-de-sesion');
    headers.delete('x-auto-hide-ip');
    headers.delete('popups');
    headers.delete('ads');
    headers.delete('view-emergent');
    headers.delete('emergent-screen');
    headers.delete('ventanas-emergentes');
    headers.delete('vistas-emergentes');
    headers.delete('google-captcha-v1');
    headers.delete('google-captcha-v2');
    headers.delete('google-captcha-v3');
    headers.delete('bot-protection');
    headers.delete('spam-protection');
    headers.delete('views-protection');
    headers.delete('login');
    headers.delete('singing');
    headers.delete('registro');
    headers.delete('inicio-de-sesion');
    headers.delete('auto-hide-ip');
    
    // Ajustes específicos para autoplay, play, start y silenciar audio en plataformas específicas
    if (url.includes('facebook.com')) {
        headers.set('x-auto-play', 'true');
        headers.set('x-play', 'true');
        headers.set('x-start', 'true');
        headers.set('auto-play', 'true');
        headers.set('play', 'true');
        headers.set('start', 'true');
        headers.set('x-auto-view', 'true');
        headers.set('x-view', 'true');
        headers.set('x-play', 'true');
        headers.set('x-autoplay', 'true');
        headers.set('auto-view', 'true');
        headers.set('view', 'true');
        headers.set('play', 'true');
        headers.set('autoplay', 'true');
    } else if (url.includes('instagram.com')) {
        headers.set('x-auto-play', 'true');
        headers.set('x-play', 'true');
        headers.set('x-start', 'true');
        headers.set('auto-play', 'true');
        headers.set('play', 'true');
        headers.set('start', 'true');
        headers.set('x-auto-view', 'true');
        headers.set('x-view', 'true');
        headers.set('x-play', 'true');
        headers.set('x-autoplay', 'true');
        headers.set('auto-view', 'true');
        headers.set('view', 'true');
        headers.set('play', 'true');
        headers.set('autoplay', 'true');
    } else if (url.includes('tiktok.com')) {
        headers.set('x-auto-play', 'true');
        headers.set('x-play', 'true');
        headers.set('x-start', 'true');
        headers.set('auto-play', 'true');
        headers.set('play', 'true');
        headers.set('start', 'true');
        headers.set('x-auto-view', 'true');
        headers.set('x-view', 'true');
        headers.set('x-play', 'true');
        headers.set('x-autoplay', 'true');
        headers.set('auto-view', 'true');
        headers.set('view', 'true');
        headers.set('play', 'true');
        headers.set('autoplay', 'true');
    } else if (url.includes('youtube.com')) {
        headers.set('x-auto-play', 'true');
        headers.set('x-play', 'true');
        headers.set('x-start', 'true');
        headers.set('auto-play', 'true');
        headers.set('play', 'true');
        headers.set('start', 'true');
        headers.set('x-auto-view', 'true');
        headers.set('x-view', 'true');
        headers.set('x-play', 'true');
        headers.set('x-autoplay', 'true');
        headers.set('auto-view', 'true');
        headers.set('view', 'true');
        headers.set('play', 'true');
        headers.set('autoplay', 'true');
    }

    headers.set('x-auto-view', 'true');
    headers.set('x-view', 'true');
    headers.set('x-play', 'true');
    headers.set('x-autoplay', 'true');
    headers.set('auto-view', 'true');
    headers.set('view', 'true');
    headers.set('play', 'true');
    headers.set('autoplay', 'true');
}

// Método para ocultar la IP, IPv4 y la ubicación de la solicitud
function anonymizeRequest(request) {
    const anonymizedHeaders = new Headers(request.headers);
    anonymizedHeaders.set('cf-ipcountry', faker.address.countryCode());
    anonymizedHeaders.set('cf-connecting-ip', faker.internet.ipv4());
    anonymizedHeaders.set('Geolocation', `${faker.address.latitude()}, ${faker.address.longitude()}`);
    return anonymizedHeaders;
}

// Método para procesar solicitudes
async function fetchAndApply(request, bypass = false) {
    try {
        const ip_address = generateFakeIP();
        const user_agent = generateFakeUserAgent();
        const region = faker.address.countryCode();
        const geolocation = generateFakeGeolocation();
        const fake_time = generateFakeTime();

        const requestOptions = {
            url: request.url,
            method: request.method,
            headers: new Headers(request.headers),
            body: request.body
        };

        modifyHeaders(requestOptions.headers, request.url);

        const original_response = await processRequest(request.url, request.method, requestOptions.headers, requestOptions.body);

        if (requestOptions.headers.get("Upgrade")?.toLowerCase() === "websocket") {
            return original_response;
        }

        const response_headers = new Headers(original_response.headers);
        const status = original_response.status;

        if (disable_cache) {
            response_headers.set('Cache-Control', 'no-store');
        }

        response_headers.set('access-control-allow-origin', '*');
        response_headers.set('access-control-allow-credentials', 'true');
        response_headers.delete('content-security-policy');
        response_headers.delete('content-security-policy-report-only');
        response_headers.delete('clear-site-data');

        if (response_headers.get("x-pjax-url")) {
            response_headers.set("x-pjax-url", response_headers.get("x-pjax-url").replace(`//${url.hostname}`, `//${requestOptions.headers.get('host')}`));
        }

        const content_type = response_headers.get('content-type');
        let original_text = '';

        if (content_type?.includes('text/html') && content_type.includes('UTF-8')) {
            original_text = await replace_response_text(original_response, url.hostname, requestOptions.headers.get('host'));
        } else {
            original_text = await original_response.text();
        }

        if ((original_text.includes('insufficient_quota') ||
            original_text.includes('rate_limit_exceeded') ||
            original_text.includes('invalid_request_error') ||
            original_text.includes('You didn\'t provide an API key')) && !bypass) {
            return await fetchAndApply(request, true);
        }

        if (original_text.includes('A 1xxx error occured.')) {
            return new Response('Custom Response: A Cloudflare Route Error Occurred', { status: 200, headers: response_headers });
        }

        return new Response(original_text, { status, headers: response_headers });

    } catch (err) {
        console.error('Error occurred:', err);
        return new Response('Internal Server Error', { status: 500 });
    }
}

const server = http.createServer(async (req, res) => {
    if (req.method === 'CONNECT') {
        const [host, port] = req.url.split(':');
        const clientSocket = net.connect(port, host, () => {
            res.writeHead(200, { 'Connection': 'Established' });
            res.pipe(clientSocket).pipe(res);
        });
        clientSocket.on('error', (err) => {
            console.error('Error occurred in CONNECT request:', err);
            res.writeHead(500);
            res.end('Internal Server Error');
        });
        return;
    }

    let body = [];
    req.on('data', chunk => {
        body.push(chunk);
    }).on('end', async () => {
        body = Buffer.concat(body).toString();

        const request = {
            url: req.url,
            method: req.method,
            headers: anonymizeRequest(req),
            body: body
        };

        const proxyResponse = await fetchAndApply(request);

        res.writeHead(proxyResponse.status, Object.fromEntries(proxyResponse.headers.entries()));
        res.end(await proxyResponse.text());
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Proxy server is running on port ${PORT}`);
});
