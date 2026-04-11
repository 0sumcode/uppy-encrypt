import UppyEncrypt from './UppyEncrypt';
import UppyDecrypt, { type DecryptedMetaData } from './UppyDecrypt';
import _sodium from 'libsodium-wrappers-sumo';
import { BasePlugin as _BasePlugin, type Uppy } from '@uppy/core';

interface UppyEncryptPluginOptions {
  id?: string;
  password?: string | null;
}

// Uppy 3 exposed `BasePlugin<TOptions>` (1 generic); Uppy 4 exposes
// `BasePlugin<Opts, M, B, PluginState>` where Opts/M/B have no defaults.
// Cast to a structural type covering the BasePlugin instance surface that
// `uppy.use()` type-checks against on both majors — including setOptions,
// getPluginState, setPluginState which Uppy 3's `.use()` requires.
// Runtime behavior is identical: the real BasePlugin supplies these.
const BasePluginCompat = _BasePlugin as unknown as new (
  uppy: Uppy,
  opts?: unknown,
) => {
  id: string;
  type: string;
  uppy: Uppy;
  install(): void;
  uninstall(): void;
  setOptions(newOpts: Partial<Record<string, unknown>>): void;
  getPluginState(): Record<string, unknown>;
  // Uppy 3's BasePlugin.setPluginState returns Record<string, unknown>.
  // Declaring void here makes TS reject the class as a BasePlugin subtype
  // (return types are covariant), forcing `.use()` to fall through to
  // UIPlugin and fail. A real return type is also valid against Uppy 4
  // (where it's void), since returning-a-value is assignable to void.
  setPluginState(update?: Partial<Record<string, unknown>>): Record<string, unknown>;
  update(state?: unknown): void;
  afterUpdate(): void;
  // The remaining members exist on Uppy 3/4/5's `BasePlugin` but were absent
  // from earlier versions of this shim. Without them, `uppy.use<T extends
  // typeof BasePlugin<any, M, B>>(UppyEncryptPlugin)` fails structural
  // assignability and consumers need a cast. `any` (not `unknown`) is required
  // for the data members because TS checks property types invariantly — the
  // shim's type must be assignable to the real `OptionalPluralizeLocale`/`I18n`
  // shapes, and only `any` is bidirectionally compatible. Real values come
  // from runtime BasePlugin inheritance and are never accessed by consumers.
  defaultLocale: any;
  i18n: any;
  i18nArray: any;
  VERSION: string;
  i18nInit(): void;
  addTarget(plugin: any): HTMLElement | null;
};

// Sodium is initialized automatically within UppyEncrypt / UppyDecrypt
// Optionally call this to ensure initialization
let sodiumIsReady = false;
export const uppyEncryptReady = async () => {
  if (!sodiumIsReady) {
    await _sodium.ready;
    sodiumIsReady = true;
  }
};

export class UppyEncryptPlugin extends BasePluginCompat {
  opts: UppyEncryptPluginOptions;

  constructor(uppy: Uppy, opts?: UppyEncryptPluginOptions) {
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
          name: `${file.name}.enc`,
          type: 'application/octet-stream',
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

export { UppyEncrypt, UppyDecrypt, DecryptedMetaData };
