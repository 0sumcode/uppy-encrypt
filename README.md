# Uppy Encrypt

An [Uppy](https://uppy.io/) Plugin to encrypt files on the browser before it's uploaded. Uppy Encrypt also comes with the ability to decrypt browser-side.

Uppy Encrypt uses [libsodium.js](https://github.com/jedisct1/libsodium.js) for all the cryptographical magic.

## Installation

```bash
npm i uppy-encrypt
```

## Encryption Example
```javascript
import { Uppy } from '@uppy/core';
import UppyEncryptPlugin from 'uppy-encrypt';

const uppy = new Uppy();
uppy.use(UppyEncryptPlugin);

// Optional: Set password manually, or disregard and a random password will be auto-generated
// uppy.setMeta({ password: '$upers3cret!' });

uppy.on('complete', async (result) => {
  for (const file of result.successful) {
    const salt = file.meta.encryption.salt; // Salt value used to increase security
    const header = file.meta.encryption.header; // Header encryption data to kick off the decryption process
    const hash = file.meta.encryption.hash; // Secure 1-way hash of the password
    const meta = file.meta.encryption.meta;  // Encrypted file meta data (file name, type)
    // ^ These are all safe to store in a database
  }
});
```

## Decryption Example
```javascript
import { UppyDecrypt, uppyEncryptReady } from 'uppy-encrypt';

// Use the values generated from the encryption process
// Usually, these would be stored/retrieved from a database
const decrypt = async (hash, password, salt, header, meta, encryptedFileUrl) => {
  // Ensure required libraries are loaded
  await uppyEncryptReady();

  // Verify provided password against the stored hash value
  if (!UppyDecrypt.verifyPassword(hash, password)) {
    // Invalid password
    return;
  }

  // Decrypt Metadata
  const decryptor = new UppyDecrypt(password, salt, header);
  const decryptedMeta = decryptor.getDecryptedMetaData(meta.header, meta.data);

  // Fetch & Decrypt the encrypted file
  const file = await fetch(encryptedFileUrl);
  const blob = await file.blob();
  const decrypted = await decryptor.decryptFile(blob);

  // Do something with the decrypted file, like download it
  if (decrypted) {
    const aElement = document.createElement('a');
    aElement.setAttribute('download', decryptedMeta.name);
    const href = URL.createObjectURL(decrypted);
    aElement.href = href;
    aElement.setAttribute('target', '_blank');
    aElement.click();
    URL.revokeObjectURL(href);
  }
}
```
