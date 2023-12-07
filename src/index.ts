import { UppyEncrypt } from './UppyEncrypt';
import { BasePlugin, type DefaultPluginOptions, Uppy } from '@uppy/core';

interface UppyEncryptPluginOptions extends DefaultPluginOptions {
  password: string;
}

export class UppyEncryptPlugin extends BasePlugin {
  opts: UppyEncryptPluginOptions;

  constructor(uppy: Uppy, opts?: UppyEncryptPluginOptions | undefined) {
    super(uppy, opts);
    this.id = opts?.id ?? 'UppyEncryptPlugin';
    this.type = 'modifier';

    const defaultOptions = {
      password: UppyEncrypt.generatePassword(),
    };
    this.opts = { ...defaultOptions, ...opts };

    this.encryptFiles = this.encryptFiles.bind(this);
  }

  async encryptFiles(fileIds: string[]) {
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
          UppyEncrypt: {
            salt: enc.getSalt(),
            header: enc.getHeader(),
            passwordHash: enc.getPasswordHash(),
            encryptedMeta: enc.getEncryptMetaData(),
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

export const generatePassword = UppyEncrypt.generatePassword;
