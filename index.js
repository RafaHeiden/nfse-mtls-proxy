const http = require('http');
const https = require('https');
const forge = require('node-forge');

const PORT = process.env.PORT || 3000;
const PROXY_SECRET = process.env.NFSE_PROXY_SECRET;

const server = http.createServer(async (req, res) => {
    console.log(`[Proxy] ${req.method} ${req.url}`);
    
    if (req.method !== 'POST') {
        res.writeHead(405, { 'Content-Type': 'text/plain' });
        res.end('Method Not Allowed');
        return;
    }

    if (req.headers['x-proxy-secret'] !== PROXY_SECRET) {
        console.log('[Proxy] Invalid secret');
        res.writeHead(403, { 'Content-Type': 'text/plain' });
        res.end('Forbidden: Invalid proxy secret');
        return;
    }

    let body = '';
    req.on('data', chunk => { body += chunk.toString(); });

    req.on('end', async () => {
        try {
            const { targetUrl, pfxBase64, pfxPassword, payload, soapAction, contentType } = JSON.parse(body);
            console.log(`[Proxy] Connecting to: ${targetUrl}`);
            console.log(`[Proxy] SOAPAction: ${soapAction}`);

            // Decode PFX
            const pfxDer = forge.util.decode64(pfxBase64);
            const pfxAsn1 = forge.asn1.fromDer(pfxDer);
            const pfx = forge.pkcs12.pkcs12FromAsn1(pfxAsn1, pfxPassword);

            const keyBags = pfx.getBags({ bagType: '1.2.840.113549.1.12.10.1.2' })['1.2.840.113549.1.12.10.1.2'];
            const certBags = pfx.getBags({ bagType: '1.2.840.113549.1.12.10.1.3' })['1.2.840.113549.1.12.10.1.3'];

            if (!keyBags?.length || !certBags?.length) {
                throw new Error('Could not find key or certificate in PFX');
            }

            const key = forge.pki.privateKeyToPem(keyBags[0].key);
            const cert = forge.pki.certificateToPem(certBags[0].cert);

            const targetUrlParsed = new URL(targetUrl);

            const options = {
                hostname: targetUrlParsed.hostname,
                port: targetUrlParsed.port || 443,
                path: targetUrlParsed.pathname + targetUrlParsed.search,
                method: 'POST',
                headers: {
                    'Content-Type': contentType || 'text/xml; charset=utf-8',
                    'Content-Length': Buffer.byteLength(payload, 'utf8'),
                    ...(soapAction && { 'SOAPAction': soapAction }),
                },
                key: key,
                cert: cert,
                rejectUnauthorized: false, // SimplISS may have self-signed cert
            };

            console.log('[Proxy] Making mTLS request...');

            const proxyReq = https.request(options, (proxyRes) => {
                console.log(`[Proxy] Response status: ${proxyRes.statusCode}`);
                
                let responseBody = '';
                proxyRes.on('data', chunk => { responseBody += chunk; });
                proxyRes.on('end', () => {
                    console.log(`[Proxy] Response body (first 500): ${responseBody.substring(0, 500)}`);
                    res.writeHead(proxyRes.statusCode, {
                        'Content-Type': proxyRes.headers['content-type'] || 'text/xml',
                    });
                    res.end(responseBody);
                });
            });

            proxyReq.on('error', (e) => {
                console.error('[Proxy] Request error:', e.message);
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end(`Proxy error: ${e.message}`);
            });

            // Send SOAP XML directly (not JSON)
            proxyReq.write(payload);
            proxyReq.end();

        } catch (error) {
            console.error('[Proxy] Error:', error.message);
            res.writeHead(500, { 'Content-Type': 'text/plain' });
            res.end(`Proxy error: ${error.message}`);
        }
    });
});

server.listen(PORT, () => {
    console.log(`[Proxy] mTLS Proxy listening on port ${PORT}`);
});
