"use strict";
//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
Object.defineProperty(exports, "__esModule", { value: true });
const ByteArray_1 = require("../internal/ByteArray");
const Native = require("../../../Native");
class PniCredentialResponse extends ByteArray_1.default {
    constructor(contents) {
        super(contents, Native.PniCredentialResponse_CheckValidContents);
    }
}
exports.default = PniCredentialResponse;
//# sourceMappingURL=PniCredentialResponse.js.map