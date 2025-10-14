const express = require('express');
const Busboy = require('busboy');
const forge = require('node-forge');

const app = express();

app.post('/decypher', (req, res) => {
  const busboy = new Busboy({ headers: req.headers });

  let privateKeyPem = '';
  let encryptedBuffer = Buffer.alloc(0);

  busboy.on('file', (fieldname, file, filename, encoding, mimetype) => {
    const chunks = [];

    file.on('data', (data) => {
      chunks.push(data);
    });

    file.on('end', () => {
      const fileData = Buffer.concat(chunks);

      if (fieldname === 'key') {
        privateKeyPem = fileData.toString();
      } else if (fieldname === 'secret') {
        encryptedBuffer = fileData;
      }
    });
  });

  busboy.on('finish', () => {
    try {
      // Проверяем, что оба файла получены
      if (!privateKeyPem || encryptedBuffer.length === 0) {
        return res.status(400).send('Missing key or secret files');
      }

      const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
      
      // Пробуем разные методы расшифровки
      let decrypted;
      try {
        // Сначала пробуем RSA-OAEP
        decrypted = privateKey.decrypt(encryptedBuffer.toString('binary'), 'RSA-OAEP');
      } catch (e) {
        // Если не сработало, пробуем RSAES-PKCS1-V1_5
        decrypted = privateKey.decrypt(encryptedBuffer.toString('binary'), 'RSAES-PKCS1-V1_5');
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
  res.send('viktoriya_09'); // Ваш логин
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
