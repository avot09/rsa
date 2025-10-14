const express = require('express');
const Busboy = require('busboy');
const forge = require('node-forge');

const app = express();

app.post('/decypher', (req, res) => {
  const busboy = new Busboy({ headers: req.headers });

  let privateKeyPem = '';
  let encryptedData = '';

  busboy.on('file', (fieldname, file, filename, encoding, mimetype) => {
    const chunks = [];

    file.on('data', (data) => {
      chunks.push(data);
    });

    file.on('end', () => {
      const fileData = Buffer.concat(chunks).toString('utf8');

      if (fieldname === 'key') {
        privateKeyPem = fileData;
      } else if (fieldname === 'secret') {
        encryptedData = fileData.trim();
      }
    });
  });

  busboy.on('finish', () => {
    try {
      if (!privateKeyPem || !encryptedData) {
        return res.status(400).send('Missing key or secret files');
      }

      const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
      
      // Декодируем из base64
      const binaryData = forge.util.decode64(encryptedData);
      
      let decrypted;
      try {
        // Пробуем RSA-OAEP
        decrypted = privateKey.decrypt(binaryData, 'RSA-OAEP', {
          md: forge.md.sha256.create()
        });
      } catch (e) {
        // Пробуем RSAES-PKCS1-V1_5
        decrypted = privateKey.decrypt(binaryData, 'RSAES-PKCS1-V1_5');
      }
      
      res.setHeader('Content-Type', 'text/plain');
      res.send(decrypted);
      
    } catch (err) {
      console.error('Decryption error:', err.message);
      res.status(500).send('Decryption error: ' + err.message);
    }
  });

  req.pipe(busboy);
});

app.get('/login', (req, res) => {
  res.setHeader('Content-Type', 'text/plain');
  res.send('viktoriya_09');
});

app.get('/', (req, res) => {
  res.send(`
    <h1>Decryption Service</h1>
    <p>Endpoints:</p>
    <ul>
      <li><a href="/login">/login</a> - returns login</li>
      <li>/decypher - POST multipart/form-data for decryption</li>
    </ul>
  `);
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log('Server started on port ' + PORT);
});
