import express from 'express';
import multer from 'multer';
import crypto from 'crypto';

const app = express();

// Настройка multer для обработки файлов в памяти
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

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
        console.log('Received request to /decypher');
        
        if (!req.files || !req.files['key'] || !req.files['secret']) {
            return res.status(400).send('Missing key or secret files');
        }

        const keyFile = req.files['key'][0];
        const secretFile = req.files['secret'][0];

        const privateKey = keyFile.buffer.toString();
        const encryptedData = secretFile.buffer.toString();

        console.log('Private key received');
        console.log('Encrypted data received');

        // Расшифровываем данные
        const decrypted = decryptWithPrivateKey(encryptedData, privateKey);
        
        console.log('Decryption successful');
        res.setHeader('Content-Type', 'text/plain');
        res.send(decrypted);

    } catch (error) {
        console.error('Decryption error:', error);
        res.status(500).send('Decryption error: ' + error.message);
    }
});

function decryptWithPrivateKey(encryptedData, privateKey) {
    try {
        // Убедимся, что данные в правильном формате
        const encryptedBuffer = Buffer.from(encryptedData.trim(), 'base64');
        
        const decrypted = crypto.privateDecrypt(
            {
                key: privateKey,
                padding: crypto.constants.RSA_PKCS1_PADDING,
            },
            encryptedBuffer
        );
        
        return decrypted.toString('utf8');
    } catch (error) {
        console.error('Decryption failed:', error.message);
        throw new Error(`Failed to decrypt: ${error.message}`);
    }
}

// Корневой route
app.get('/', (req, res) => {
    res.send(`
        <h1>Decryption Service</h1>
        <p>Endpoints:</p>
        <ul>
            <li><a href="/login">/login</a> - returns login</li>
            <li>/decypher - POST endpoint for decryption</li>
        </ul>
        <p>Server is running!</p>
    `);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
});
