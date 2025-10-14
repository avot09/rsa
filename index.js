const express = require('express');
const Busboy = require('busboy');
const forge = require('node-forge');

const app = express();

// Добавляем корневой route
app.get('/', (req, res) => {
  res.send(`
    <h1>Decryption Service</h1>
    <p>Service is running correctly!</p>
    <p>Endpoints:</p>
    <ul>
      <li><a href="/login">/login</a> - returns login</li>
      <li>/decypher - POST endpoint for decryption</li>
    </ul>
  `);
});

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
      // Проверяем что файлы получены
      if (!privateKeyPem || encryptedBuffer.length === 0) {
        return res.status(400).send('Missing key or secret files');
      }

      const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
      
      // Пробуем оба метода на случай если OAEP не сработает
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

  req.pipe(busboy);
});

app.get('/login', (req, res) => {
  res.setHeader('Content-Type', 'text/plain');
  res.send('viktoriya_09'); // Ваш логин
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log('Server started on port ' + PORT);
});
