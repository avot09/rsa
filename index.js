const express = require('express');
const multer = require('multer');
const forge = require('node-forge');

const app = express();
const upload = multer({ storage: multer.memoryStorage() }); // Store files in memory

// Root route for testing
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
      <head><title>Keys</title><meta charset="utf-8"></head>
      <body>
        <h1>RSA Decryption Service</h1>
        <form target="ifr" action="/decypher" method="POST" enctype="multipart/form-data">
          Ключ: <input type="file" name="key"><br>
          Секрет: <input type="file" name="secret"><hr>
          <input type="submit">
        </form>
        <iframe src="" name="ifr" frameborder="0"></iframe>
        <p><a href="/login">Check Login</a></p>
      </body>
    </html>
  `);
});

// /decypher route
app.post('/decypher', upload.fields([{ name: 'key', maxCount: 1 }, { name: 'secret', maxCount: 1 }]), (req, res) => {
  console.log('Received /decypher request'); // Log for debugging
  try {
    if (!req.files || !req.files.key || !req.files.secret) {
      console.log('Missing files: key or secret not provided');
      return res.status(400).send('Missing key or secret files');
    }

    const privateKeyPem = req.files.key[0].buffer.toString('utf8').trim();
    const encryptedBuffer = req.files.secret[0].buffer;
    console.log(`Key length: ${privateKeyPem.length}, Secret length: ${encryptedBuffer.length}`); // Log sizes
    console.log(`Key preview: ${privateKeyPem.substring(0, 50)}...`); // Log key start

    // Convert PKCS#8 to RSA PEM if needed
    let keyPem = privateKeyPem;
    if (privateKeyPem.includes('-----BEGIN PRIVATE KEY-----')) {
      try {
        const pkcs8 = forge.pkcs8.privateKeyFromAsn1(forge.asn1.fromDer(forge.util.createBuffer(privateKeyPem)));
        keyPem = forge.pki.privateKeyToPem(pkcs8);
        console.log('Converted PKCS#8 to RSA PEM');
      } catch (convErr) {
        console.log('PKCS#8 conversion failed, using original:', convErr.message);
      }
    }

    const privateKey = forge.pki.privateKeyFromPem(keyPem);
    const encryptedBytes = forge.util.createBuffer(encryptedBuffer);
    const decrypted = privateKey.decrypt(encryptedBytes, 'RSAES-PKCS1-V1_5'); // Try PKCS#1
    const result = decrypted.toString().trim().replace('\n', '').replace('\r', '');
    console.log(`Decrypted result preview: ${result.substring(0, 20)}...`); // Log result
    res.send(result);
  } catch (err) {
    console.error('Decryption error:', err.message, err.stack); // Detailed error log
    res.status(400).send('Ошибка расшифровки: ' + err.message);
  }
});

// /login route
app.get('/login', (req, res) => {
  console.log('Received /login request');
  res.send('viktoriya_09');
});

// Use Render's assigned port
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
