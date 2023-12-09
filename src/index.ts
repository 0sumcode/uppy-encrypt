import UppyEncrypt from './UppyEncrypt';
import UppyDecrypt from './UppyDecrypt';
import _sodium from 'libsodium-wrappers-sumo';
import { BasePlugin, type DefaultPluginOptions, Uppy } from '@uppy/core';

interface UppyEncryptPluginOptions extends DefaultPluginOptions {
  password: string | null;
}

// Init sodium, makes a callback when library is ready
let uppyEncryptReady: Function = () => {};
export const onUppyEncryptReady = (fn: Function) => {
  uppyEncryptReady = fn;
};
(async () => {
  await _sodium.ready;
  uppyEncryptReady();
})();

export class UppyEncryptPlugin extends BasePlugin {
  opts: UppyEncryptPluginOptions;

  constructor(uppy: Uppy, opts?: UppyEncryptPluginOptions | undefined) {
    super(uppy, opts);
    this.id = opts?.id ?? 'UppyEncryptPlugin';
    this.type = 'modifier';

    const defaultOptions = {
      password: null,
    };
    this.opts = { ...defaultOptions, ...opts };

    this.encryptFiles = this.encryptFiles.bind(this);
  }

  async encryptFiles(fileIds: string[]) {
    // Generate a password here if none is already set
    this.opts.password = this.opts.password || UppyEncrypt.generatePassword();

    // Add password to meta data so it can be referenced externally
    this.uppy.setMeta({ password: this.opts.password });

    for (const fileId of fileIds) {
      const file = this.uppy.getFile(fileId);
      const enc = new UppyEncrypt(this.uppy, file, this.opts.password);
      if (await enc.encryptFile()) {
        this.uppy.emit('preprocess-complete', file);
        let blob = await enc.getEncryptedFile();
        this.uppy.setFileState(fileId, {
          type: 'application/octet-stream',
          data: blob,
          size: blob.size,
        });

        this.uppy.setFileMeta(fileId, {
          encryption: {
            salt: enc.getSalt(),
            header: enc.getHeader(),
            hash: enc.getPasswordHash(),
            meta: enc.getEncryptMetaData(),
          },
        });
      }
    }
  }

  install() {
    this.uppy.addPreProcessor(this.encryptFiles);
  }

  uninstall() {
    this.uppy.removePreProcessor(this.encryptFiles);
  }
}

export { UppyEncrypt, UppyDecrypt };
