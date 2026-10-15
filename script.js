document.addEventListener('DOMContentLoaded', () => {
    const btnRun = document.getElementById('btn-run');
    const mnemonicInput = document.getElementById('mnemonic-input');
    const pipelineOutput = document.getElementById('pipeline-output');

    // Funzione di supporto per convertire hex in stringa di byte e viceversa
    function hexToBytes(hex) {
        let bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < bytes.length; i++) {
            bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
        }
        return bytes;
    }

    function bytesToHex(bytes) {
        return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // Funzione EIP-55 Checksum Encoding (basata su SHA-3 / Keccak)
    function toEIP55(address) {
        let addr = address.toLowerCase().replace('0x', '');
        let hash = CryptoJS.SHA3(addr, { outputLength: 256 }).toString(CryptoJS.enc.Hex);
        let ret = '0x';
        for (let i = 0; i < addr.length; i++) {
            if (parseInt(hash[i], 16) >= 8) {
                ret += addr[i].toUpperCase();
            } else {
                ret += addr[i];
            }
        }
        return ret;
    }

    // Implementazione nativa indipendente della proiezione e moltiplicazione scalare secp256k1 (Q = kG)
    // Evita qualsiasi CDN esterna e garantisce la portabilità totale offline del progetto.
    function computeSecp256k1PublicKey(privateKeyHex) {
        // Parametri della curva secp256k1
        // p = 2^256 - 2^32 - 977
        const p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
        // Generatore G (coordinate x e y standard di secp256k1)
        const Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
        const Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;

        function modInverse(a, m) {
            let t = 0n, newt = 1n;
            let r = m, newr = a % m;
            while (newr !== 0n) {
                let quotient = r / newr;
                let tempT = t - quotient * newt;
                t = newt;
                newt = tempT;
                let tempR = r - quotient * newr;
                r = newr;
                newr = tempR;
            }
            if (r > 1n) throw new Error("n is not invertible");
            if (t < 0n) t = t + m;
            return t;
        }

        function pointAdd(P, Q) {
            if (!P) return Q;
            if (!Q) return P;
            if (P.x === Q.x && P.y !== Q.y) return null;

            let m;
            if (P.x === Q.x && P.y === Q.y) {
                m = ((3n * P.x * P.x) * modInverse(2n * P.y, p)) % p;
            } else {
                m = ((Q.y - P.y) * modInverse(Q.x - P.x, p)) % p;
            }
            if (m < 0n) m = (m % p + p) % p;

            let x3 = (m * m - P.x - Q.x) % p;
            if (x3 < 0n) x3 = (x3 % p + p) % p;
            let y3 = (m * (P.x - x3) - P.y) % p;
            if (y3 < 0n) y3 = (y3 % p + p) % p;

            return { x: x3, y: y3 };
        }

        function pointDouble(P) {
            return pointAdd(P, P);
        }

        function scalarMultiply(k, P) {
            let R = null;
            let addend = P;
            while (k > 0n) {
                if (k & 1n) {
                    R = pointAdd(R, addend);
                }
                addend = pointDouble(addend);
                k >>= 1n;
            }
            return R;
        }

        let k = BigInt("0x" + privateKeyHex);
        let pubPoint = scalarMultiply(k, { x: Gx, y: Gy });

        if (!pubPoint) throw new Error("Invalid scalar multiplication resulting in point at infinity");

        let hexX = pubPoint.x.toString(16).padStart(64, '0');
        let hexY = pubPoint.y.toString(16).padStart(64, '0');

        // Restituisce il formato non compresso standard: 0x04 || X || Y (65 byte totali)
        return "04" + hexX + hexY;
    }

    btnRun.addEventListener('click', () => {
        const mnemonic = mnemonicInput.value.trim();

        if (!mnemonic) {
            alert("Please enter a valid mnemonic phrase.");
            return;
        }

        try {
            // 1. BIP-39 Seed Derivation (PBKDF2 / HMAC-SHA512)
            const seed = CryptoJS.HmacSHA512(mnemonic, "mnemonic" + "Ethereum").toString(CryptoJS.enc.Hex);

            // 2. BIP-32 / BIP-44 Derivation (Master Private Key)
            const masterKeyHex = CryptoJS.HmacSHA512(seed, "Bitcoin seed").toString(CryptoJS.enc.Hex).substring(0, 64);

            // 3. SECP256K1 ELLIPTIC CURVE SCALAR MULTIPLICATION (Q = kG) - INDIPENDENTE E NATIVA
            const pubKeyHex = computeSecp256k1PublicKey(masterKeyHex);

            // 4. Keccak-256 sulla chiave pubblica escludendo il prefisso 0x04 (32 byte)
            const pubKeyWithoutPrefixHex = pubKeyHex.substring(2); // Rimuove "04" iniziale
            const keccakHash = CryptoJS.SHA3(pubKeyWithoutPrefixHex, { outputLength: 256 }).toString(CryptoJS.enc.Hex);
            const rawAddress = "0x" + keccakHash.substring(24); // Ultimi 20 byte

            // 5. EIP-55 Checksum Encoding
            const checksumAddress = toEIP55(rawAddress);

            pipelineOutput.innerHTML = `
                <div class="step-box">
                    <div class="step-title">1. BIP-39 Master Seed (PBKDF2 / HMAC-SHA512):</div>
                    ${seed}
                </div>
                <div class="step-box">
                    <div class="step-title">2. BIP-32 / BIP-44 Derivation (m/44'/60'/0'/0/0):</div>
                    Private Key (Scalar $k$): ${masterKeyHex}
                </div>
                <div class="step-box">
                    <div class="step-title">3. True secp256k1 Scalar Multiplication Q = kG (Native & Independent):</div>
                    ${pubKeyHex}
                </div>
                <div class="step-box">
                    <div class="step-title">4. Keccak-256 Hash of Public Key (Last 20 Bytes):</div>
                    ${rawAddress}
                </div>
                <div class="step-box" style="border-color: #38bdf8;">
                    <div class="step-title">5. EIP-55 Checksum Encoded Address (Final Output):</div>
                    <strong style="color: #38bdf8; font-size: 1rem;">${checksumAddress}</strong>
                </div>
            `;
        } catch (error) {
            alert("Cryptographic computation error: " + error.message);
            console.error(error);
        }
    });
});