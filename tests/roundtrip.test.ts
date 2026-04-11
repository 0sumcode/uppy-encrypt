import { describe, it, expect, beforeAll } from 'vitest';
import { Uppy } from '@uppy/core';
import { UppyEncrypt, UppyDecrypt, uppyEncryptReady } from '../src/index';

beforeAll(async () => {
  await uppyEncryptReady();
});

function makeUppyWithFile(name: string, type: string, data: BlobPart) {
  const uppy = new Uppy();
  const blob = new Blob([data], { type });
  const fileId = uppy.addFile({ name, type, data: blob });
  return { uppy, file: uppy.getFile(fileId), blob };
}

describe('UppyEncrypt / UppyDecrypt round-trip', () => {
  it('round-trips a small text file', async () => {
    const original = 'Hello, encrypted world! Lorem ipsum dolor sit amet.';
    const { uppy, file, blob } = makeUppyWithFile('hello.txt', 'text/plain', original);

    const password = 'super-secret-pw';
    const enc = new UppyEncrypt(uppy, file, password);
    expect(await enc.encryptFile()).toBe(true);

    const encryptedBlob = await enc.getEncryptedFile();
    expect(encryptedBlob.size).toBeGreaterThan(blob.size);

    const dec = new UppyDecrypt(password, enc.getSalt(), enc.getHeader());
    const meta = enc.getEncryptMetaData();
    const decryptedMeta = dec.getDecryptedMetaData(meta.header, meta.data);
    expect(decryptedMeta.name).toBe('hello.txt');
    expect(decryptedMeta.type).toBe('text/plain');

    const decryptedBlob = await dec.decryptFile(encryptedBlob);
    expect(await decryptedBlob.text()).toBe(original);
  });

  it('round-trips a binary payload byte-for-byte', async () => {
    const bytes = new Uint8Array(8192);
    for (let i = 0; i < bytes.length; i++) bytes[i] = (i * 31 + 7) & 0xff;
    const { uppy, file } = makeUppyWithFile('pattern.bin', 'application/octet-stream', bytes);

    const password = UppyEncrypt.generatePassword();
    const enc = new UppyEncrypt(uppy, file, password);
    expect(await enc.encryptFile()).toBe(true);
    const encryptedBlob = await enc.getEncryptedFile();

    const dec = new UppyDecrypt(password, enc.getSalt(), enc.getHeader());
    const meta = enc.getEncryptMetaData();
    dec.getDecryptedMetaData(meta.header, meta.data);
    const decryptedBlob = await dec.decryptFile(encryptedBlob);
    const decryptedBytes = new Uint8Array(await decryptedBlob.arrayBuffer());
    expect(decryptedBytes).toEqual(bytes);
  });

});

describe('password helpers', () => {
  it('generatePassword returns a URL-safe base64 string', () => {
    const pw = UppyEncrypt.generatePassword();
    expect(pw).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(pw.length).toBeGreaterThan(0);
  });

  it('generatePassword returns a fresh value each call', () => {
    const a = UppyEncrypt.generatePassword();
    const b = UppyEncrypt.generatePassword();
    expect(a).not.toBe(b);
  });

  it('verifyPassword accepts the correct password and rejects wrong ones', async () => {
    const { uppy, file } = makeUppyWithFile('x.txt', 'text/plain', 'x');
    const enc = new UppyEncrypt(uppy, file, 'correct-horse');
    const hash = enc.getPasswordHash();

    expect(UppyDecrypt.verifyPassword(hash, 'correct-horse')).toBe(true);
    expect(UppyDecrypt.verifyPassword(hash, 'wrong-password')).toBe(false);
  });

  it('decryption with the wrong password fails', async () => {
    const { uppy, file } = makeUppyWithFile('secret.txt', 'text/plain', 'top secret');
    const enc = new UppyEncrypt(uppy, file, 'right');
    await enc.encryptFile();
    const encryptedBlob = await enc.getEncryptedFile();

    const dec = new UppyDecrypt('wrong', enc.getSalt(), enc.getHeader());
    await expect(dec.decryptFile(encryptedBlob)).rejects.toThrow();
  });
});
