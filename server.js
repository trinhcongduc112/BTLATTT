const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

const app = express();
const port = process.env.PORT || 3000;

// Middleware bảo mật
app.use(helmet());

// Cấu hình rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 phút
    max: 100 // giới hạn mỗi IP gửi tối đa 100 yêu cầu trong 15 phút
});
app.use(limiter);

// Middleware CORS và JSON
app.use(cors());
app.use(express.json({ limit: '10kb' }));

// Pigpen Cipher mapping
const pigpenMap = {
    'A': ']', 'B': 'L', 'C': 'J', 'D': 'U', 'E': 'D', 'F': 'C', 'G': '>', 'H': '<', 'I': '^',
    'J': 'V', 'K': ']', 'L': 'L', 'M': 'J', 'N': 'U', 'O': 'D', 'P': 'C', 'Q': '>', 'R': '<',
    'S': '^', 'T': 'V', 'U': ']', 'V': 'L', 'W': 'J', 'X': 'U', 'Y': 'D', 'Z': 'C'
};

// Bảng giải mã Pigpen Cipher
const pigpenReverseMap = {
    ']': 'A', 'L': 'B', 'J': 'C', 'U': 'D', 'D': 'E', 'C': 'F', '>': 'G', '<': 'H', '^': 'I',
    'V': 'J', ']': 'K', 'L': 'L', 'J': 'M', 'U': 'N', 'D': 'O', 'C': 'P', '>': 'Q', '<': 'R',
    '^': 'S', 'V': 'T', ']': 'U', 'L': 'V', 'J': 'W', 'U': 'X', 'D': 'Y', 'C': 'Z'
};

// Hàm Caesar Cipher
function caesarCipher(text, shift) {
    return text.split('').map(char => {
        if (/[a-zA-Z]/.test(char)) {  // Kiểm tra nếu ký tự là chữ cái
            const start = char === char.toUpperCase() ? 65 : 97; // 65 là mã ASCII của 'A', 97 là mã ASCII của 'a'
            return String.fromCharCode(((char.charCodeAt(0) - start + shift) % 26) + start); // Mã hóa hoặc giải mã
        }
        return char; // Nếu không phải chữ cái, giữ nguyên
    }).join('');
}

// API cho Pigpen Cipher
app.post('/pigpen/encrypt', async (req, res) => {
    try {
        const { text } = req.body;
        if (!text) {
            return res.status(400).json({ error: 'Text là bắt buộc' });
        }
        const ciphertext = text.toUpperCase().split('').map(char => pigpenMap[char] || char).join('');
        res.json({ ciphertext });
    } catch (error) {
        console.error('Lỗi khi mã hóa Pigpen:', error);
        res.status(500).json({ error: 'Lỗi server' });
    }
});

app.post('/pigpen/decrypt', async (req, res) => {
    try {
        const { text } = req.body;
        if (!text) {
            return res.status(400).json({ error: 'Text là bắt buộc' });
        }
        const plaintext = text.split('').map(char => pigpenReverseMap[char] || char).join('');
        res.json({ plaintext });
    } catch (error) {
        console.error('Lỗi khi giải mã Pigpen:', error);
        res.status(500).json({ error: 'Lỗi server' });
    }
});

// API cho Caesar Cipher
app.post('/caesar/encrypt', async (req, res) => {
    try {
        const { text, shift } = req.body;
        if (!text || shift === undefined) {
            return res.status(400).json({ error: 'Text và shift là bắt buộc' });
        }
        const ciphertext = caesarCipher(text, parseInt(shift));
        res.json({ ciphertext });
    } catch (error) {
        console.error('Lỗi khi mã hóa Caesar:', error);
        res.status(500).json({ error: 'Lỗi server' });
    }
});

app.post('/caesar/decrypt', async (req, res) => {
    try {
        const { text, shift } = req.body;
        if (!text || shift === undefined) {
            return res.status(400).json({ error: 'Text và shift là bắt buộc' });
        }
        const plaintext = caesarCipher(text, -parseInt(shift));
        res.json({ plaintext });
    } catch (error) {
        console.error('Lỗi khi giải mã Caesar:', error);
        res.status(500).json({ error: 'Lỗi server' });
    }
});

// Hàm mã hóa/giải mã Vigenère
function vigenereCipher(text, key, encrypt = true) {
    const processedKey = key.toUpperCase().replace(/[^A-Z]/g, '');
    if (!processedKey) return text;

    return text
        .split('')
        .map((char, i) => {
            if (char.match(/[a-z]/i)) {
                const isUpperCase = char === char.toUpperCase();
                const base = isUpperCase ? 65 : 97;
                const charCode = char.toUpperCase().charCodeAt(0) - 65;
                const keyChar = processedKey[i % processedKey.length].charCodeAt(0) - 65;
                const shift = encrypt ? keyChar : (26 - keyChar);
                const newChar = String.fromCharCode(((charCode + shift) % 26) + base);
                return isUpperCase ? newChar.toUpperCase() : newChar.toLowerCase();
            }
            return char;
        })
        .join('');
}

// API cho Vigenère Cipher
app.post('/vigenere/encrypt', async (req, res) => {
    try {
        const { text, key } = req.body;
        if (!text || !key) {
            return res.status(400).json({ error: 'Text và key là bắt buộc' });
        }
        const ciphertext = vigenereCipher(text, key, true);
        res.json({ ciphertext });
    } catch (error) {
        console.error('Lỗi khi mã hóa Vigenère:', error);
        res.status(500).json({ error: 'Lỗi server' });
    }
});

app.post('/vigenere/decrypt', async (req, res) => {
    try {
        const { text, key } = req.body;
        if (!text || !key) {
            return res.status(400).json({ error: 'Text và key là bắt buộc' });
        }
        const plaintext = vigenereCipher(text, key, false);
        res.json({ plaintext });
    } catch (error) {
        console.error('Lỗi khi giải mã Vigenère:', error);
        res.status(500).json({ error: 'Lỗi server' });
    }
});

// Hàm mã hóa/giải mã Vigenère Autokey
function vigenereAutokeyCipher(text, key, encrypt = true) {
    const processedKey = key.toUpperCase().replace(/[^A-Z]/g, '');
    if (!processedKey) return text;

    let fullKey = processedKey;
    if (encrypt) {
        fullKey += text.toUpperCase().replace(/[^A-Z]/g, '');
    }

    let result = '';
    let keyIndex = 0;

    for (let i = 0; i < text.length; i++) {
        if (text[i].match(/[a-z]/i)) {
            const isUpperCase = text[i] === text[i].toUpperCase();
            const base = isUpperCase ? 65 : 97;
            const charCode = text[i].toUpperCase().charCodeAt(0) - 65;
            const keyChar = fullKey[keyIndex].charCodeAt(0) - 65;
            const shift = encrypt ? keyChar : (26 - keyChar);
            const newChar = String.fromCharCode(((charCode + shift) % 26) + base);
            result += isUpperCase ? newChar.toUpperCase() : newChar.toLowerCase();

            if (!encrypt) {
                fullKey += newChar.toUpperCase();
            }
            keyIndex++;
        } else {
            result += text[i];
        }
    }
    return result;
}

// Hàm tạo ma trận Playfair
function generatePlayfairMatrix(key) {
    key = key.toUpperCase().replace(/J/g, 'I').replace(/[^A-Z]/g, '');
    const matrix = Array(5).fill().map(() => Array(5).fill(''));
    const used = new Set();
    let r = 0, c = 0;

    // Thêm các ký tự từ key vào ma trận
    for (let char of key) {
        if (!used.has(char)) {
            matrix[r][c] = char;
            used.add(char);
            c++;
            if (c === 5) {
                c = 0;
                r++;
            }
        }
    }

    // Thêm các ký tự còn lại của bảng chữ cái
    for (let char of 'ABCDEFGHIKLMNOPQRSTUVWXYZ') {
        if (!used.has(char)) {
            matrix[r][c] = char;
            used.add(char);
            c++;
            if (c === 5) {
                c = 0;
                r++;
            }
        }
    }

    return matrix;
}

// Hàm tìm vị trí ký tự trong ma trận Playfair
function findPosition(matrix, char) {
    for (let i = 0; i < 5; i++) {
        for (let j = 0; j < 5; j++) {
            if (matrix[i][j] === char) {
                return [i, j];
            }
        }
    }
    return null;
}

// Hàm mã hóa/giải mã Playfair
function playfairCipher(text, key, encrypt = true) {
    text = text.toUpperCase().replace(/J/g, 'I').replace(/[^A-Z]/g, '');
    if (text.length % 2 !== 0) text += 'X';

    const matrix = generatePlayfairMatrix(key);
    let result = '';

    for (let i = 0; i < text.length; i += 2) {
        const [r1, c1] = findPosition(matrix, text[i]);
        const [r2, c2] = findPosition(matrix, text[i + 1]);

        let newChar1, newChar2;

        if (r1 === r2) { // Cùng hàng
            newChar1 = matrix[r1][(c1 + (encrypt ? 1 : 4)) % 5];
            newChar2 = matrix[r2][(c2 + (encrypt ? 1 : 4)) % 5];
        } else if (c1 === c2) { // Cùng cột
            newChar1 = matrix[(r1 + (encrypt ? 1 : 4)) % 5][c1];
            newChar2 = matrix[(r2 + (encrypt ? 1 : 4)) % 5][c2];
        } else { // Tạo hình chữ nhật
            newChar1 = matrix[r1][c2];
            newChar2 = matrix[r2][c1];
        }

        result += newChar1 + newChar2;
    }

    return { ciphertext: result, matrix };
}

// API cho Vigenère Autokey
app.post('/vigenere-autokey/encrypt', async (req, res) => {
    try {
        const { text, key } = req.body;
        if (!text || !key) {
            return res.status(400).json({ error: 'Text và key là bắt buộc' });
        }
        const ciphertext = vigenereAutokeyCipher(text, key, true);
        res.json({ ciphertext });
    } catch (error) {
        console.error('Lỗi khi mã hóa Vigenère Autokey:', error);
        res.status(500).json({ error: 'Lỗi server' });
    }
});

app.post('/vigenere-autokey/decrypt', async (req, res) => {
    try {
        const { text, key } = req.body;
        if (!text || !key) {
            return res.status(400).json({ error: 'Text và key là bắt buộc' });
        }
        const plaintext = vigenereAutokeyCipher(text, key, false);
        res.json({ plaintext });
    } catch (error) {
        console.error('Lỗi khi giải mã Vigenère Autokey:', error);
        res.status(500).json({ error: 'Lỗi server' });
    }
});

// API cho Playfair
app.post('/playfair/encrypt', async (req, res) => {
    try {
        const { text, key } = req.body;
        if (!text || !key) {
            return res.status(400).json({ error: 'Text và key là bắt buộc' });
        }
        const { ciphertext, matrix } = playfairCipher(text, key, true);
        res.json({ ciphertext, matrix });
    } catch (error) {
        console.error('Lỗi khi mã hóa Playfair:', error);
        res.status(500).json({ error: 'Lỗi server' });
    }
});

app.post('/playfair/decrypt', async (req, res) => {
    try {
        const { text, key } = req.body;
        if (!text || !key) {
            return res.status(400).json({ error: 'Text và key là bắt buộc' });
        }
        const { ciphertext: plaintext, matrix } = playfairCipher(text, key, false);
        res.json({ plaintext, matrix });
    } catch (error) {
        console.error('Lỗi khi giải mã Playfair:', error);
        res.status(500).json({ error: 'Lỗi server' });
    }
});

// Middleware xử lý lỗi
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Có lỗi xảy ra trên server' });
});

// Xử lý lỗi 404
app.use((req, res) => {
    res.status(404).json({ error: 'Không tìm thấy API này' });
});

// Lắng nghe yêu cầu trên port
app.listen(port, () => {
    console.log(`Server chạy trên cổng ${port}`);
});
