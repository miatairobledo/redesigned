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

// Function to disable SSL certificate verification
function disableSSLVerification() {
    return new https.Agent({ rejectUnauthorized: false });
}

const agent = proxy_host && proxy_port ? new HttpsProxyAgent({
    host: proxy_host,
    port: proxy_port,
    auth: proxy_auth,
    rejectUnauthorized: false
}) : disableSSLVerification();

// Function to process HTTP/HTTPS requests
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

async function replaceResponseText(response, upstreamDomain, hostName) {
    let text = await response.text();
    for (const [key, value] of Object.entries(replace_dict)) {
        const re = new RegExp(key, 'g');
        text = text.replace(re, key === '$upstream' ? upstreamDomain : hostName);
    }
    return text;
}

function generateFakeIP() {
    return faker.internet.ip();
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

    // Delete unwanted headers
    const unwantedHeaders = [
        'g-recaptcha-response', 'google-captcha-response', 'google-site-verification', 'cf-ray', 'cf-request-id',
        'h-captcha-response', 'x-captcha-id', 'x-captcha-token', 'x-instagram-ajax', 'x-requested-with', 'origin',
        'x-csrftoken', 'x-ig-app-id', 'x-ig-www-claim', 'x-ig-origin-region', 'x-ig-connection-type', 'x-ig-capabilities',
        'x-ig-app-module', 'x-fb-http-engine', 'x-fb-host', 'captcha-id', 'captcha-token', 'instagram-ajax',
        'requested-with', 'origin', 'csrftoken', 'ig-app-id', 'ig-www-claim', 'ig-origin-region', 'ig-connection-type',
        'ig-capabilities', 'ig-app-module', 'fb-http-engine', 'fb-host', 'Sec-Ch-Ua', 'Sec-Ch-Ua-Mobile',
        'Sec-Ch-Ua-Platform', 'Sec-Fetch-Dest', 'Sec-Fetch-Mode', 'Sec-Fetch-Site', 'Sec-Fetch-User', 'Dpr',
        'Viewport-Width', 'Downlink', 'Ect', 'Rtt', 'Accept-Encoding', 'X-Requested-With', 'X-Forwarded-For', 'Via',
        'Cookie', 'x-popups', 'x-ads', 'x-view-emergent', 'x-emergent-screen', 'x-ventanas-emergentes',
        'x-vistas-emergentes', 'x-google-captcha-v1', 'x-google-captcha-v2', 'x-google-captcha-v3', 'x-bot-protection',
        'x-spam-protection', 'x-views-protection', 'x-login', 'x-singing', 'x-registro', 'x-inicio-de-sesion',
        'x-auto-hide-ip', 'popups', 'ads', 'view-emergent', 'emergent-screen', 'ventanas-emergentes', 'vistas-emergentes',
        'google-captcha-v1', 'google-captcha-v2', 'google-captcha-v3', 'bot-protection', 'spam-protection',
        'views-protection', 'login', 'singing', 'registro', 'inicio-de-sesion', 'auto-hide-ip'
    ];
    
    for (const header of unwantedHeaders) {
        headers.delete(header);
    }

    headers.set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36');
    headers.set('Referer', 'https://www.google.com/');

    // Specific adjustments for autoplay
    if (url.includes('facebook.com') || url.includes('instagram.com') || url.includes('tiktok.com') || url.includes('youtube.com')) {
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
}

function anonymizeRequest(request) {
    const anonymizedHeaders = new Headers(request.headers);
    anonymizedHeaders.set('cf-ipcountry', faker.address.countryCode());
    anonymizedHeaders.set('cf-connecting-ip', faker.internet.ip());
    anonymizedHeaders.set('Geolocation', `${faker.address.latitude()}, ${faker.address.longitude()}`);
    return anonymizedHeaders;
}

async function fetchAndApply(request, bypass = false) {
    try {
        const requestOptions = {
            url: request.url,
            method: request.method,
            headers: new Headers(request.headers),
            body: request.body
        };

        modifyHeaders(requestOptions.headers, request.url);

        const originalResponse = await processRequest(request.url, request.method, requestOptions.headers, requestOptions.body);

        if (requestOptions.headers.get("Upgrade")?.toLowerCase() === "websocket") {
            return originalResponse;
        }

        const responseHeaders = new Headers(originalResponse.headers);
        const status = originalResponse.status;

        if (disable_cache) {
            responseHeaders.set('Cache-Control', 'no-store');
        }

        responseHeaders.set('access-control-allow-origin', '*');
        responseHeaders.set('access-control-allow-credentials', 'true');
        responseHeaders.delete('content-security-policy');
        responseHeaders.delete('content-security-policy-report-only');
        responseHeaders.delete('clear-site-data');

        if (responseHeaders.get("x-pjax-url")) {
            responseHeaders.set("x-pjax-url", responseHeaders.get("x-pjax-url").replace(`//${new URL(request.url).hostname}`, `//${requestOptions.headers.get('host')}`));
        }

        const contentType = responseHeaders.get('content-type');
        let originalText = '';

        if (contentType?.includes('text/html') && contentType.includes('UTF-8')) {
            originalText = await replaceResponseText(originalResponse, new URL(request.url).hostname, requestOptions.headers.get('host'));
        } else {
            originalText = await originalResponse.text();
        }

        if ((originalText.includes('insufficient_quota') ||
            originalText.includes('rate_limit_exceeded') ||
            originalText.includes('invalid_request_error') ||
            originalText.includes('You didn\'t provide an API key')) && !bypass) {
            return await fetchAndApply(request, true);
        }

        if (originalText.includes('A 1xxx error occured.')) {
            return new Response('Custom Response: A Cloudflare Route Error Occurred', { status: 200, headers: responseHeaders });
        }

        return new Response(originalText, { status, headers: responseHeaders });

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
