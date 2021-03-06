"use strict";
//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
Object.defineProperty(exports, "__esModule", { value: true });
const ByteArray_1 = require("../internal/ByteArray");
const Native = require("../../../Native");
const ProfileKeyCommitment_1 = require("./ProfileKeyCommitment");
const ProfileKeyVersion_1 = require("./ProfileKeyVersion");
const UUIDUtil_1 = require("../internal/UUIDUtil");
class ProfileKey extends ByteArray_1.default {
    constructor(contents) {
        super(contents, ProfileKey.checkLength(ProfileKey.SIZE));
    }
    getCommitment(uuid) {
        return new ProfileKeyCommitment_1.default(Native.ProfileKey_GetCommitment(this.contents, (0, UUIDUtil_1.fromUUID)(uuid)));
    }
    getProfileKeyVersion(uuid) {
        return new ProfileKeyVersion_1.default(Native.ProfileKey_GetProfileKeyVersion(this.contents, (0, UUIDUtil_1.fromUUID)(uuid)));
    }
}
exports.default = ProfileKey;
ProfileKey.SIZE = 32;
//# sourceMappingURL=ProfileKey.js.map