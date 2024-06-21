import fetch from 'node-fetch';
import faker from 'faker';
import http from 'http';
import { URL } from 'url';

const { Headers, Response } = fetch;

const upstream = 'api.openai.com';
const upstream_path = '/';
const upstream_mobile = upstream;
const httpsProtocol = true;
const disable_cache = false;
const replace_dict = {
    '$upstream': '$custom_domain'
};

async function device_status(user_agent_info) {
    const agents = ["Android", "iPhone", "SymbianOS", "Windows Phone", "iPad", "iPod"];
    return !agents.some(agent => user_agent_info.includes(agent));
}

async function replace_response_text(response, upstream_domain, host_name) {
    let text = await response.text();
    for (let i in replace_dict) {
        const j = replace_dict[i];
        const re = new RegExp(i, 'g');
        text = text.replace(re, i === '$upstream' ? upstream_domain : host_name);
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

async function fetchAndApply(request) {
    try {
        const ip_address = generateFakeIP();
        const user_agent = generateFakeUserAgent();
        const region = faker.address.countryCode();
        const geolocation = generateFakeGeolocation();
        const fake_time = generateFakeTime();

        const url = new URL(request.url, `http://${request.headers.host}`);
        const url_hostname = url.hostname;

        url.protocol = httpsProtocol ? 'https:' : 'http:';
        const upstream_domain = await device_status(user_agent) ? upstream : upstream_mobile;

        url.host = upstream_domain;
        url.pathname = upstream_path + url.pathname;

        const request_headers = new Headers();
        for (const [key, value] of Object.entries(request.headers)) {
            request_headers.append(key, value);
        }

        request_headers.set('Host', upstream_domain);
        request_headers.set('Referer', `${url.protocol}//${url_hostname}`);
        request_headers.set('cf-ipcountry', region);
        request_headers.set('cf-connecting-ip', ip_address);
        request_headers.set('User-Agent', user_agent);
        request_headers.set('Geolocation', geolocation);
        request_headers.set('Date', fake_time);

        request_headers.delete('Authorization');
        request_headers.delete('apikey');
        request_headers.delete('x-api-key');

        const original_response = await fetch(url.href, {
            method: request.method,
            headers: request_headers,
            body: request.body
        });

        if (request_headers.get("Upgrade")?.toLowerCase() === "websocket") {
            return original_response;
        }

        const original_response_clone = original_response.clone();
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
            response_headers.set("x-pjax-url", response_headers.get("x-pjax-url").replace(`//${upstream_domain}`, `//${url_hostname}`));
        }

        const content_type = response_headers.get('content-type');
        const original_text = content_type?.includes('text/html') && content_type.includes('UTF-8')
            ? await replace_response_text(original_response_clone, upstream_domain, url_hostname)
            : await original_response_clone.text();

        return new Response(original_text, { status, headers: response_headers });

    } catch (err) {
        console.error('Error occurred:', err);
        return new Response('Internal Server Error', { status: 500 });
    }
}

const server = http.createServer(async (req, res) => {
    let body = [];
    req.on('data', chunk => {
        body.push(chunk);
    }).on('end', async () => {
        body = Buffer.concat(body).toString();

        const request = {
            url: req.url,
            method: req.method,
            headers: req.headers,
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
