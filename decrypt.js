const { decryptText } = require('./cipher');
const { writeFile, readFile } = require('fs').promises;
const { ENCRYPTION_SALT, HASH_SALT } = require('./salt/salt.js');
const { promisify } = require('util');
const pbkdf2 = promisify(require('crypto').pbkdf2);

const [,,fileName, pwd] = process.argv;

(async () => {
    try {
        const originalHash = JSON.parse(await readFile('./hash/hash.json', 'utf8'));

        const {encrypted, iv} = JSON.parse(await readFile(fileName, 'utf8'));
        const decrypted = await decryptText(encrypted, pwd, ENCRYPTION_SALT, iv);
        console.log('Hash that will be decrypted\n', encrypted);
        console.log('Result:', decrypted);

        const newHash = (await pbkdf2(decrypted, HASH_SALT, 100000, 64, 'sha512')).toString('hex');

        if (newHash === originalHash) {
            console.log('Files are the same');
            await writeFile(fileName, decrypted, 'utf8');
            console.log(`Done, you have just decrypted ${fileName}`);
        } else {
            console.error('These files are not the same!');
        }
    } catch (err) {
        if (err.code === 'ENOENT') {
            console.error('This file does not exist!', err);
        } else {
            console.error('Oh no!', err);
        }
    }
})();
