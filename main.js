import fetch from 'node-fetch';
import faker from 'faker';
import http from 'http';
import { URL } from 'url';

const { Headers } = fetch;

const upstream = 'api.openai.com';
const upstream_path = '/';
const upstream_mobile = upstream;
const httpsProtocol = true;
const disable_cache = false;
const replace_dict = {
    '$upstream': '$custom_domain'
};

async function device_status(user_agent_info) {
    var agents = ["Android", "iPhone", "SymbianOS", "Windows Phone", "iPad", "iPod"];
    var flag = true;
    for (var v = 0; v < agents.length; v++) {
        if (user_agent_info.indexOf(agents[v]) > 0) {
            flag = false;
            break;
        }
    }
    return flag;
}

async function replace_response_text(response, upstream_domain, host_name) {
    let text = await response.text();
    for (let i in replace_dict) {
        let j = replace_dict[i];
        let re = new RegExp(i, 'g');
        if (i === '$upstream') {
            text = text.replace(re, upstream_domain);
        } else if (i === '$custom_domain') {
            text = text.replace(re, host_name);
        }
        if (j === '$upstream') {
            text = text.replace(re, upstream_domain);
        } else if (j === '$custom_domain') {
            text = text.replace(re, host_name);
        }
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

        let url = new URL(request.url, `http://${request.headers.host}`);
        let url_hostname = url.hostname;

        if (httpsProtocol) {
            url.protocol = 'https:';
        } else {
            url.protocol = 'http:';
        }

        const upstream_domain = await device_status(user_agent) ? upstream : upstream_mobile;

        url.host = upstream_domain;
        url.pathname = upstream_path + url.pathname;

        let method = request.method;
        let request_headers = new Headers(request.headers);

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

        let original_response = await fetch(url.href, {
            method: method,
            headers: request_headers,
            body: request
        });

        let connection_upgrade = request_headers.get("Upgrade");
        if (connection_upgrade && connection_upgrade.toLowerCase() === "websocket") {
            return original_response;
        }

        let original_response_clone = original_response.clone();
        let original_text = null;
        let response_headers = original_response.headers;
        let new_response_headers = new Headers(response_headers);
        let status = original_response.status;

        if (disable_cache) {
            new_response_headers.set('Cache-Control', 'no-store');
        }

        new_response_headers.set('access-control-allow-origin', '*');
        new_response_headers.set('access-control-allow-credentials', 'true');
        new_response_headers.delete('content-security-policy');
        new_response_headers.delete('content-security-policy-report-only');
        new_response_headers.delete('clear-site-data');

        if (new_response_headers.get("x-pjax-url")) {
            new_response_headers.set("x-pjax-url", response_headers.get("x-pjax-url").replace(`//${upstream_domain}`, `//${url_hostname}`));
        }

        const content_type = new_response_headers.get('content-type');
        if (content_type != null && content_type.includes('text/html') && content_type.includes('UTF-8')) {
            original_text = await replace_response_text(original_response_clone, upstream_domain, url_hostname);
        } else {
            original_text = await original_response_clone.text();
        }

        response = new Response(original_text, {
            status,
            headers: new_response_headers
        });

        return response;
    } catch (err) {
        console.error('Error occurred:', err);
        return new Response('Internal Server Error', { status: 500 });
    }
}

const server = http.createServer(async (req, res) => {
    const request = {
        url: req.url,
        method: req.method,
        headers: req.headers,
        body: req
    };

    const proxyResponse = await fetchAndApply(request);

    res.writeHead(proxyResponse.status, Object.fromEntries(proxyResponse.headers.entries()));
    res.end(await proxyResponse.text());
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Proxy server is running on port ${PORT}`);
});
