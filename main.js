import fetch from 'node-fetch';
import faker from 'faker';
const { Headers } = fetch;

const upstream = 'api.openai.com';
const upstream_path = '/';
const upstream_mobile = upstream;
const blocked_region = [];
const blocked_ip_address = [];
const https = true;
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

async function fetchAndApply(request) {
    try {
        const region = faker.address.countryCode();
        let ip_address = generateFakeIP();
        const user_agent = generateFakeUserAgent();
        const geolocation = generateFakeGeolocation();
        
        let response = null;
        let url = new URL(request.url);
        let url_hostname = url.hostname;
        
        if (https) {
            url.protocol = 'https:';
        } else {
            url.protocol = 'http:';
        }
        
        const upstream_domain = await device_status(user_agent) ? upstream : upstream_mobile;
        
        url.host = upstream_domain;
        url.pathname = upstream_path + url.pathname;
        
        if (blocked_region.includes(region)) {
            response = new Response('Access denied: WorkersProxy is not available in your region yet.', { status: 403 });
        } else if (blocked_ip_address.includes(ip_address)) {
            response = new Response('Access denied: Your IP address is blocked by WorkersProxy.', { status: 403 });
        } else {
            let method = request.method;
            let request_headers = new Headers(request.headers);
            
            request_headers.set('Host', upstream_domain);
            request_headers.set('Referer', `${url.protocol}//${url_hostname}`);
            
            request_headers.delete('Authorization');
            request_headers.delete('apikey');
            request_headers.delete('x-api-key');
            
            request_headers.set('cf-ipcountry', region);
            request_headers.set('cf-ip-geo', geolocation);
            
            request_headers.set('cf-connecting-ip', ip_address);
            
            let original_response = await fetch(url.href, {
                method: method,
                headers: request_headers,
                body: request.body
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
        }
        return response;
    } catch (err) {
        console.error('Error occurred:', err);
        return new Response('Internal Server Error', { status: 500 });
    }
}

addEventListener('fetch', event => {
    event.respondWith(fetchAndApply(event.request));
});

export { fetchAndApply };
