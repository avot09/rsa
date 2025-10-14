import express from 'express';
import multer from 'multer';
import crypto from 'crypto';

const app = express();
const upload = multer({ storage: multer.memoryStorage() });

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Endpoint 1: /login
app.get('/login', (req, res) => {
    res.setHeader('Content-Type', 'text/plain');
    res.send('viktoriya_09');
});

// Endpoint 2: /decypher
app.post('/decypher', upload.fields([
    { name: 'key', maxCount: 1 },
    { name: 'secret', maxCount: 1 }
]), (req, res) => {
    try {
        console.log('=== DECYPHER REQUEST START ===');
        
        if (!req.files || !req.files['key'] || !req.files['secret']) {
            return res.status(400).send('Missing key or secret files');
        }

        const keyFile = req.files['key'][0];
        const secretFile = req.files['secret'][0];

        const privateKey = keyFile.buffer.toString('utf8').trim();
        let encryptedData = secretFile.buffer.toString('utf8').trim();

        console.log('Private key length:', privateKey.length);
        console.log('Encrypted data length:', encryptedData.length);
        console.log('Encrypted data:', encryptedData);

        // Убираем возможные лишние символы
        encryptedData = encryptedData.replace(/\r\n/g, '').replace(/\n/g, '');

        // Расшифровываем данные
        const decrypted = decryptWithPrivateKey(encryptedData, privateKey);
        
        console.log('Decryption successful:', decrypted);
        console.log('=== DECYPHER REQUEST END ===');
        
        res.setHeader('Content-Type', 'text/plain');
        res.send(decrypted);

    } catch (error) {
        console.error('DECRYPTION ERROR:', error.message);
        res.status(500).send('Decryption error: ' + error.message);
    }
});

function decryptWithPrivateKey(encryptedData, privateKey) {
    try {
        console.log('Starting decryption...');
        console.log('Encrypted data type:', typeof encryptedData);
        console.log('Encrypted data sample:', encryptedData.substring(0, 200));

        // Пробуем разные варианты декодирования
        let encryptedBuffer;
        
        // Вариант 1: Прямое base64 декодирование
        try {
            encryptedBuffer = Buffer.from(encryptedData, 'base64');
            console.log('Base64 decoded buffer length:', encryptedBuffer.length);
        } catch (e) {
            console.log('Base64 decoding failed, trying as raw text');
            encryptedBuffer = Buffer.from(encryptedData, 'utf8');
        }

        // Если данные все еще слишком маленькие, пробуем hex
        if (encryptedBuffer.length < 128) {
            console.log('Buffer too small, trying hex decoding');
            try {
                encryptedBuffer = Buffer.from(encryptedData, 'hex');
                console.log('Hex decoded buffer length:', encryptedBuffer.length);
            } catch (e) {
                console.log('Hex decoding also failed');
            }
        }

        console.log('Final buffer length:', encryptedBuffer.length);

        // Пробуем разные методы расшифровки
        let decrypted;
        
        try {
            // Метод 1: PKCS1 padding
            decrypted = crypto.privateDecrypt(
                {
                    key: privateKey,
                    padding: crypto.constants.RSA_PKCS1_PADDING,
                },
                encryptedBuffer
            );
        } catch (e) {
            console.log('PKCS1 failed, trying OAEP:', e.message);
            
            // Метод 2: OAEP padding
            decrypted = crypto.privateDecrypt(
                {
                    key: privateKey,
                    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                },
                encryptedBuffer
            );
        }

        const result = decrypted.toString('utf8');
        console.log('Decrypted result:', result);
        
        return result;

    } catch (error) {
        console.error('Decryption function error:', error.message);
        
        // Дополнительная диагностика
        if (error.message.includes('too small')) {
            throw new Error('Encrypted data is too small. Check if data is properly encoded in base64.');
        } else if (error.message.includes('wrong final block length')) {
            throw new Error('Wrong block length. Check padding method.');
        } else {
            throw new Error(`Decryption failed: ${error.message}`);
        }
    }
}

// Тестовый endpoint для проверки
app.post('/test-decypher', express.text({ type: '*/*' }), (req, res) => {
    try {
        const { key, secret } = JSON.parse(req.body);
        const decrypted = decryptWithPrivateKey(secret, key);
        res.send(decrypted);
    } catch (error) {
        res.status(500).send('Test error: ' + error.message);
    }
});

// Корневой route
app.get('/', (req, res) => {
    res.send(`
        <h1>Decryption Service - DEBUG</h1>
        <p>Endpoints:</p>
        <ul>
            <li><a href="/login">/login</a> - returns login</li>
            <li>/decypher - POST multipart/form-data</li>
        </ul>
    `);
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
});
