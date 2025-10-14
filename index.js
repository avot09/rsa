import express from 'express';
import multer from 'multer';
import crypto from 'crypto';

const app = express();
const upload = multer();

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Endpoint 1: /login
app.get('/login', (req, res) => {
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

        console.log('Private key length:', privateKey.length);
        console.log('Encrypted data length:', encryptedData.length);

        // Расшифровываем данные
        const decrypted = decryptWithPrivateKey(encryptedData, privateKey);
        
        console.log('Decryption successful');
        res.send(decrypted);

    } catch (error) {
        console.error('Decryption error:', error);
        res.status(500).send('Decryption error: ' + error.message);
    }
});

function decryptWithPrivateKey(encryptedData, privateKey) {
    try {
        const encryptedBuffer = Buffer.from(encryptedData.trim(), 'base64');
        
        const decrypted = crypto.privateDecrypt(
            {
                key: privateKey,
                padding: crypto.constants.RSA_PKCS1_PADDING,
            },
            encryptedBuffer
        );
        
        return decrypted.toString();
    } catch (error) {
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
    `);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
