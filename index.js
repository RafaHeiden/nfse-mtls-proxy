const http = require('http');
const https = require('https');
const forge = require('node-forge');

const PORT = process.env.PORT || 3000;
const PROXY_SECRET = process.env.NFSE_PROXY_SECRET;

const server = http.createServer(async (req, res) => {
    if (req.method !== 'POST') {
        res.writeHead(405, { 'Content-Type': 'text/plain' });
        res.end('Method Not Allowed');
        return;
    }

    if (req.headers['x-proxy-secret'] !== PROXY_SECRET) {
        res.writeHead(403, { 'Content-Type': 'text/plain' });
        res.end('Forbidden: Invalid proxy secret');
        return;
    }

    let body = '';
    req.on('data', chunk => {
        body += chunk.toString();
    });

    req.on('end', async () => {
        try {
            const { targetUrl, pfxBase64, pfxPassword, contentType, soapAction, authorization, body: requestBody } = JSON.parse(body);

            const pfxDer = forge.util.decode64(pfxBase64);
            const pfxAsn1 = forge.asn1.fromDer(pfxDer);
            const pfx = forge.pkcs12.pkcs12FromAsn1(pfxAsn1, pfxPassword);

            const keyBags = pfx.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag];
            const certBags = pfx.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag];

            if (!keyBags || keyBags.length === 0 || !certBags || certBags.length === 0) {
                throw new Error('Could not find key or certificate in PFX');
            }

            const key = keyBags[0].key;
            const cert = certBags[0].cert;

            const targetUrlParsed = new URL(targetUrl);

            const options = {
                hostname: targetUrlParsed.hostname,
                port: targetUrlParsed.port || 443,
                path: targetUrlParsed.pathname + targetUrlParsed.search,
                method: 'POST',
                headers: {
                    'Content-Type': contentType || 'text/xml; charset=utf-8',
                    'SOAPAction': soapAction,
                    'Authorization': authorization,
                    'Accept': 'text/xml, application/xml',
                },
                key: forge.pki.privateKeyToPem(key),
                cert: forge.pki.certificateToPem(cert),
                rejectUnauthorized: true,
            };

            console.log(`[Proxy] Connecting to: ${targetUrl}`);

            const proxyReq = https.request(options, (proxyRes) => {
                res.writeHead(proxyRes.statusCode, { 'Content-Type': proxyRes.headers['content-type'] || 'text/xml' });
                proxyRes.pipe(res);
            });

            proxyReq.on('error', (e) => {
                console.error('Proxy request error:', e);
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end(`Proxy request failed: ${e.message}`);
            });

            proxyReq.write(requestBody);
            proxyReq.end();

        } catch (error) {
            console.error('Error in proxy:', error.message);
            res.writeHead(500, { 'Content-Type': 'text/plain' });
            res.end(`Proxy error: ${error.message}`);
        }
    });
});

server.listen(PORT, () => {
    console.log(`mTLS Proxy listening on port ${PORT}`);
});
