const { encryptText } = require('./cipher');
const { readFile, writeFile } = require('fs').promises;
const { ENCRYPTION_SALT, HASH_SALT } = require('./salt/salt.js');
const { promisify } = require('util');
const pbkdf2 = promisify(require('crypto').pbkdf2);

// const fileName = process.argv[2];
// const pwd = process.argv[3];
const [,,fileName, pwd] = process.argv;

(async () => {
    try {
        const fileContent = await readFile(fileName, 'utf8');
        console.log('Content that will be encrypted\n', fileContent);

        const hash = await pbkdf2(fileContent, HASH_SALT, 100000, 64, 'sha512')
        await writeFile('./hash/hash.json', JSON.stringify(hash.toString('hex')));
        console.log('Hash saved successfully');

        const encrypted = JSON.stringify(await encryptText(fileContent, pwd, ENCRYPTION_SALT));
        await writeFile(fileName, encrypted, 'utf8');
        console.log(`Result: ${encrypted}`);

        console.log(`Done, you have just encrypted ${fileName}`);
    } catch (err) {
        if (err.code === 'ENOENT') {
            console.error('This file does not exist!', err);
        } else {
            console.error('Oh no!', err);
        }
    }
})();


