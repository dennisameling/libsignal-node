"use strict";
//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
Object.defineProperty(exports, "__esModule", { value: true });
// eslint-disable-next-line @typescript-eslint/no-require-imports, @typescript-eslint/no-var-requires
const NativeImpl = require('node-gyp-build')(__dirname + '/../..');
class ProtocolAddress {
    constructor(handle) {
        this._nativeHandle = handle;
    }
    static _fromNativeHandle(handle) {
        return new ProtocolAddress(handle);
    }
    static new(name, deviceId) {
        return new ProtocolAddress(NativeImpl.ProtocolAddress_New(name, deviceId));
    }
    name() {
        return NativeImpl.ProtocolAddress_Name(this);
    }
    deviceId() {
        return NativeImpl.ProtocolAddress_DeviceId(this);
    }
}
exports.ProtocolAddress = ProtocolAddress;
//# sourceMappingURL=Address.js.map