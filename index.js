import express from 'express';
import Busboy from 'busboy';
import forge from 'node-forge';
import https from 'https';
import fs from 'fs';

const app = express();

// Маршрут /decypher
app.post('/decypher', (req, res) => {
  const busboy = new Busboy({ headers: req.headers });
  let privateKeyPem = '';
  let encryptedBuffer = Buffer.alloc(0);

  busboy.on('file', (fieldname, file, filename, encoding, mimetype) => {
    const chunks = [];
    file.on('data', (data) => chunks.push(data));
    file.on('end', () => {
      const fileData = Buffer.concat(chunks);
      if (fieldname === 'key') {
        privateKeyPem = fileData.toString('utf8');
      } else if (fieldname === 'secret') {
        encryptedBuffer = fileData;
      }
    });
  });

  busboy.on('finish', () => {
    try {
      if (!privateKeyPem || !encryptedBuffer.length) {
        return res.status(400).send('Missing key or secret');
      }
      const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
      const decrypted = privateKey.decrypt(encryptedBuffer.toString('binary'), 'RSA-OAEP');
      res.send(decrypted.trim());
    } catch (err) {
      console.error('Decryption error:', err);
      res.status(400).send('Ошибка расшифровки: ' + err.message);
    }
  });

  req.pipe(busboy);
});

// Маршрут /login
app.get('/login', (req, res) => {
  res.send('viktoriya_09');
});

// HTTPS сервер (для локальной разработки, на Render.com HTTPS автоматический)
const PORT = process.env.PORT || 3000;
if (process.env.NODE_ENV !== 'production') {
  // Локально используем самоподписанный сертификат
  const httpsOptions = {
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem')
  };
  https.createServer(httpsOptions, app).listen(PORT, () => {
    console.log(`Server running on https://localhost:${PORT}`);
  });
} else {
  // На Render.com используем HTTP, так как SSL обрабатывается Render
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}
