const pigpenMap = {
    'A': ']', 'B': 'L', 'C': 'J', 'D': 'U', 'E': 'D', 'F': 'C', 'G': '>', 'H': '<', 'I': '^',
    'J': 'V', 'K': ']', 'L': 'L', 'M': 'J', 'N': 'U', 'O': 'D', 'P': 'C', 'Q': '>', 'R': '<',
    'S': '^', 'T': 'V', 'U': ']', 'V': 'L', 'W': 'J', 'X': 'U', 'Y': 'D', 'Z': 'C'
};

const pigpenReverseMap = Object.fromEntries(
    Object.entries(pigpenMap).map(([key, value]) => [value, key])
);

function encrypt(text) {
    if (!text) throw new Error('Text is required');
    if (text.length > 1000) throw new Error('Text too long. Maximum 1000 characters.');
    return text.toUpperCase().split('').map(char => pigpenMap[char] || char).join('');
}

function decrypt(text) {
    if (!text) throw new Error('Text is required');
    if (text.length > 1000) throw new Error('Text too long. Maximum 1000 characters.');
    return text.split('').map(char => pigpenReverseMap[char] || char).join('');
}

module.exports = {
    encrypt,
    decrypt
}; 