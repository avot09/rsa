import express from 'express';
import multer from 'multer';
import https from 'https';
import fs from 'fs';
import crypto from 'crypto';

const app = express();
const upload = multer(); // Для парсинга multipart/form-data без сохранения на диск (в память)

// HTTPS опs
const httpsOptions = {
  key: fs.readFileSync('key.pem'),  // Ваш приватный ключ сервера
  cert: fs.readFileSync('cert.pem') // Ваш сертификат сервера
};

// Маршрут /decypher
app.post('/decypher', upload.fields([{ name: 'key', maxCount: 1 }, { name: 'secret', maxCount: 1 }]), (req, res) => {
  try {
    if (!req.files || !req.files.key || !req.files.secret) {
      return res.status(400).send('Missing files: need key and secret');
    }

    const privateKeyPem = req.files.key[0].buffer.toString('utf8'); // Приватный ключ как строка PEM
    const encryptedBuffer = req.files.secret[0].buffer; // Зашифрованные данные как буфер

    // Расшифровка RSA (PKCS1 padding, стандарт для id_rsa)
    const decrypted = crypto.privateDecrypt(
      {
        key: privateKeyPem,
        padding: crypto.constants.RSA_PKCS1_PADDING
      },
      encryptedBuffer
    );

    res.send(decrypted.toString('utf8').trim()); // Возвращаем как обычную строку
  } catch (error) {
    console.error(error);
    res.status(500).send('Decryption failed: ' + error.message);
  }
});

// Маршрут /login
app.get('/login', (req, res) => {
  res.send('viktoriya_09');
});

// Запуск HTTPS сервера (порт из env или 3000, как в форме 3001 — измените при нужно)
const PORT = process.env.PORT || 3000;
https.createServer(httpsOptions, app).listen(PORT, () => {
  console.log(`Server running on https://localhost:${PORT}`);
});
