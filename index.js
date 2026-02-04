const http = require('http');
const https = require('https');
const forge = require('node-forge');

const PORT = process.env.PORT || 3000;
const PROXY_SECRET = process.env.NFSE_PROXY_SECRET;

const server = http.createServer(async (req, res) => {
    if (req.method !== 'POST') {
        res.writeHead(405, { 'Content-Type': 'text/plain' });
        return res.end('Method Not Allowed');
    }

    if (req.headers['x-proxy-secret'] !== PROXY_SECRET) {
        res.writeHead(403, { 'Content-Type': 'text/plain' });
        return res.end('Forbidden: Invalid proxy secret');
    }

    let body = '';
    req.on('data', chunk => { body += chunk.toString(); });

    req.on('end', async () => {
        try {
            const { targetUrl, pfxBase64, pfxPassword, payload } = JSON.parse(body);

            // Decode PFX certificate
            const pfxDer = forge.util.decode64(pfxBase64);
            const pfxAsn1 = forge.asn1.fromDer(pfxDer);
            const pfx = forge.pkcs12.pkcs12FromAsn1(pfxAsn1, pfxPassword);

            const keyBags = pfx.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
            const certBags = pfx.getBags({ bagType: forge.pki.oids.certBag });

            const keyBag = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag]?.[0];
            const certBag = certBags[forge.pki.oids.certBag]?.[0];

            if (!keyBag?.key || !certBag?.cert) {
                throw new Error('Could not extract key or certificate from PFX');
            }

            const targetUrlParsed = new URL(targetUrl);

            const options = {
                hostname: targetUrlParsed.hostname,
                port: targetUrlParsed.port || 443,
                path: targetUrlParsed.pathname + targetUrlParsed.search,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(JSON.stringify(payload))
                },
                key: forge.pki.privateKeyToPem(keyBag.key),
                cert: forge.pki.certificateToPem(certBag.cert),
                rejectUnauthorized: true,
            };

            const proxyReq = https.request(options, (proxyRes) => {
                res.writeHead(proxyRes.statusCode, proxyRes.headers);
                proxyRes.pipe(res);
            });

            proxyReq.on('error', (e) => {
                console.error('Proxy request error:', e.message);
                res.writeHead(502, { 'Content-Type': 'text/plain' });
                res.end(`Proxy request failed: ${e.message}`);
            });

            proxyReq.write(JSON.stringify(payload));
            proxyReq.end();

        } catch (error) {
            console.error('Proxy error:', error.message);
            res.writeHead(500, { 'Content-Type': 'text/plain' });
            res.end(`Proxy error: ${error.message}`);
        }
    });
});

server.listen(PORT, () => {
    console.log(`mTLS Proxy listening on port ${PORT}`);
});
