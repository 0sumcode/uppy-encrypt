# uppy-encrypt

## Example
```javascript
import { Uppy } from '@uppy/core';
import UppyEncryptPlugin from 'uppy-encrypt';

const uppy = new Uppy();
uppy.use(UppyEncryptPlugin);

// Optional: Set password manually, or disregard and a random password will be auto-generated
// uppy.setMeta({ password: '$upers3cret!' });
```
