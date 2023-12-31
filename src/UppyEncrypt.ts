import type { Uppy, UppyFile } from '@uppy/core';
import _sodium from 'libsodium-wrappers-sumo';
import { CHUNK_SIZE, SIGNATURE } from './constants';

// Init Sodium
let sodium: typeof _sodium;
(async () => {
  await _sodium.ready;
  sodium = _sodium;
})();

export default class UppyEncrypt {
  private uppy: Uppy;
  private password: string;
  private salt: Uint8Array;
  private key: Uint8Array;
  private state: _sodium.StateAddress;
  private header: Uint8Array;
  private file: UppyFile<Record<string, unknown>, Record<string, unknown>>;
  private stream: ReadableStream;
  private streamController: ReadableStreamDefaultController | undefined;
  private streamCanceled = false;

  private index = 0;

  constructor(uppy: Uppy, file: UppyFile<Record<string, unknown>, Record<string, unknown>>, password: string) {
    this.uppy = uppy;
    this.file = file;
    this.password = password;

    // Set Uppy event handlers that effect the encryption process
    uppy.on('cancel-all', () => {
      this.streamCanceled = true;
    });

    this.streamController;
    this.stream = new ReadableStream({
      start: (controller) => {
        this.streamController = controller;
      },
    });

    this.salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
    this.key = sodium.crypto_pwhash(
      sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES,
      password,
      this.salt,
      sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_ALG_ARGON2ID13
    );

    const res = sodium.crypto_secretstream_xchacha20poly1305_init_push(this.key);
    this.state = res.state;
    this.header = res.header;
  }

  /**
   * Helper function that generate a random password
   */
  static generatePassword() {
    return sodium.to_base64(sodium.randombytes_buf(16), sodium.base64_variants.URLSAFE_NO_PADDING);
  }

  /**
   * Encrypts the file
   */
  async encryptFile() {
    if (!this.streamController) {
      throw new Error('Encryption stream does not exist');
    }

    while (this.index < this.file.size) {
      if (this.streamCanceled) {
        await this.stream.cancel();
        return false;
      }

      // If first chunk
      if (this.index === 0) {
        this.streamController.enqueue(new Uint8Array(new TextEncoder().encode(SIGNATURE)));
        this.streamController.enqueue(this.salt);
        this.streamController.enqueue(this.header);
      }

      const tag =
        this.index + CHUNK_SIZE < this.file.size
          ? sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
          : sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL;

      const chunk = await this.file.data.slice(this.index, this.index + CHUNK_SIZE).arrayBuffer();
      const encryptedChunk = sodium.crypto_secretstream_xchacha20poly1305_push(this.state, new Uint8Array(chunk), null, tag);

      this.streamController.enqueue(new Uint8Array(encryptedChunk));

      this.uppy.emit('preprocess-progress', this.file, {
        mode: 'determinate',
        message: `Encrypting ${this.file.name}...`,
        value: this.index / this.file.size,
      });

      this.index += CHUNK_SIZE;
    }

    this.uppy.emit('preprocess-progress', this.file, {
      mode: 'determinate',
      message: `Encrypting ${this.file.name}...`,
      value: 1,
    });

    this.streamController.close();

    return true;
  }

  /**
   * Creates and returns a Blob of the encrypted file
   */
  async getEncryptedFile() {
    const response = new Response(this.stream);
    return response.blob();
  }

  /**
   * Returns an encrypted representation of the file's metadata (name, content-type)
   * header: base64-encoded header data
   * meta: Encrypted JSON string of the file's metadata, base64-encoded
   */
  getEncryptMetaData() {
    // Init fresh state
    const res = sodium.crypto_secretstream_xchacha20poly1305_init_push(this.key);

    const metaJson = JSON.stringify({ name: this.file.meta.name, type: this.file.meta.type || null });
    const encryptedChunk = sodium.crypto_secretstream_xchacha20poly1305_push(
      res.state,
      new Uint8Array(new TextEncoder().encode(metaJson)),
      null,
      sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
    );

    return {
      header: sodium.to_base64(res.header, sodium.base64_variants.URLSAFE_NO_PADDING),
      data: sodium.to_base64(encryptedChunk, sodium.base64_variants.URLSAFE_NO_PADDING),
    };
  }

  /**
   * Returns a hash of the password base64-encoded
   * This data is safe to store in a database, etc
   */
  getPasswordHash() {
    return sodium.crypto_pwhash_str(this.password, sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE, sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE);
  }

  /**
   * Returns the header base64-encoded
   * This data is safe to store in a database, etc
   */
  getHeader() {
    return sodium.to_base64(this.header, sodium.base64_variants.URLSAFE_NO_PADDING);
  }

  /**
   * Returns the salt base64-encoded
   * This data is safe to store in a database, etc
   */
  getSalt() {
    return sodium.to_base64(this.salt, sodium.base64_variants.URLSAFE_NO_PADDING);
  }
}
