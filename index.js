const express = require('express');
const multer = require('multer');
const forge = require('node-forge');

const app = express();
const upload = multer({ storage: multer.memoryStorage() });

app.post('/decypher', upload.fields([
  { name: 'key', maxCount: 1 },
  { name: 'secret', maxCount: 1 }
]), (req, res) => {
  try {
    if (!req.files || !req.files.key || !req.files.secret) {
      return res.status(400).send('Missing key or secret files');
    }

    const privateKeyPem = req.files.key[0].buffer.toString();
    const encryptedBuffer = req.files.secret[0].buffer;

    const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
    
    let decrypted;
    try {
      decrypted = privateKey.decrypt(encryptedBuffer.toString('binary'), 'RSA-OAEP');
    } catch (e) {
      decrypted = privateKey.decrypt(encryptedBuffer.toString('binary'), 'RSAES-PKCS1-V1_5');
    }
    
    res.setHeader('Content-Type', 'text/plain');
    res.send(decrypted);
    
  } catch (err) {
    console.error('Decryption error:', err.message);
    res.status(500).send('Decryption error: ' + err.message);
  }
});

app.get('/login', (req, res) => {
  res.setHeader('Content-Type', 'text/plain');
  res.send('viktoriya_09');
});

app.get('/', (req, res) => {
  res.send(`
    <h1>Decryption Service - MULTER</h1>
    <p>Using multer instead of busboy</p>
  `);
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log('Server started on port ' + PORT);
});
