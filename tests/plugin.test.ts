import { describe, it, expect, beforeAll } from 'vitest';
import { Uppy } from '@uppy/core';
import { UppyEncryptPlugin, UppyDecrypt, uppyEncryptReady } from '../src/index';

beforeAll(async () => {
  await uppyEncryptReady();
});

function getPlugin(uppy: Uppy<any, any>) {
  return uppy.getPlugin('UppyEncryptPlugin') as unknown as UppyEncryptPlugin;
}

describe('UppyEncryptPlugin', () => {
  it('encrypts a file through the preprocessor and round-trips it', async () => {
    const uppy = new Uppy();
    uppy.use(UppyEncryptPlugin, { password: 'plugin-test-pw' });

    const original = 'Plugin-level encryption test content';
    const fileId = uppy.addFile({
      name: 'plugin.txt',
      type: 'text/plain',
      data: new Blob([original], { type: 'text/plain' }),
    });

    await getPlugin(uppy).encryptFiles([fileId]);

    const file = uppy.getFile(fileId);
    expect(file.meta.name).toBe('plugin.txt.enc');
    expect(file.type).toBe('application/octet-stream');

    const encryption = (file.meta as any).encryption as {
      salt: string;
      header: string;
      hash: string;
      meta: { header: string; data: string };
    };
    expect(encryption).toBeDefined();
    expect(typeof encryption.salt).toBe('string');
    expect(typeof encryption.header).toBe('string');
    expect(typeof encryption.hash).toBe('string');
    expect(typeof encryption.meta.header).toBe('string');
    expect(typeof encryption.meta.data).toBe('string');

    expect(UppyDecrypt.verifyPassword(encryption.hash, 'plugin-test-pw')).toBe(true);

    const dec = new UppyDecrypt('plugin-test-pw', encryption.salt, encryption.header);
    const decryptedMeta = dec.getDecryptedMetaData(encryption.meta.header, encryption.meta.data);
    expect(decryptedMeta.name).toBe('plugin.txt');
    expect(decryptedMeta.type).toBe('text/plain');

    const decrypted = await dec.decryptFile(file.data as Blob);
    expect(await decrypted.text()).toBe(original);
  });

  it('auto-generates a password and stores it on uppy meta when none is provided', async () => {
    const uppy = new Uppy();
    uppy.use(UppyEncryptPlugin);
    const fileId = uppy.addFile({
      name: 'auto.txt',
      type: 'text/plain',
      data: new Blob(['auto'], { type: 'text/plain' }),
    });

    await getPlugin(uppy).encryptFiles([fileId]);

    const pw = (uppy.getState().meta as any).password as string | undefined;
    expect(typeof pw).toBe('string');
    expect(pw!.length).toBeGreaterThan(0);

    const encryption = (uppy.getFile(fileId).meta as any).encryption as { hash: string };
    expect(UppyDecrypt.verifyPassword(encryption.hash, pw!)).toBe(true);
  });

  it('emits preprocess-progress events during encryption', async () => {
    const uppy = new Uppy();
    uppy.use(UppyEncryptPlugin, { password: 'evt' });

    const progressValues: number[] = [];
    uppy.on('preprocess-progress', (_file, progress) => {
      progressValues.push((progress as { value: number }).value);
    });

    const fileId = uppy.addFile({
      name: 'evt.txt',
      type: 'text/plain',
      data: new Blob(['hello world'], { type: 'text/plain' }),
    });
    await getPlugin(uppy).encryptFiles([fileId]);

    expect(progressValues.length).toBeGreaterThan(0);
    expect(progressValues[progressValues.length - 1]).toBe(1);
  });

  it('registers as a preprocessor on install and unregisters on uninstall', () => {
    const uppy = new Uppy();
    uppy.use(UppyEncryptPlugin);
    expect(getPlugin(uppy)).toBeDefined();
    uppy.removePlugin(getPlugin(uppy));
    expect(uppy.getPlugin('UppyEncryptPlugin')).toBeUndefined();
  });
});
