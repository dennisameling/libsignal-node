"use strict";
//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = require("crypto");
const Constants_1 = require("../internal/Constants");
const Native = require("../../../Native");
const ProfileKeyCredentialRequestContext_1 = require("./ProfileKeyCredentialRequestContext");
const ProfileKeyCredential_1 = require("./ProfileKeyCredential");
const ProfileKeyCredentialPresentation_1 = require("./ProfileKeyCredentialPresentation");
const UUIDUtil_1 = require("../internal/UUIDUtil");
class ClientZkProfileOperations {
    constructor(serverPublicParams) {
        this.serverPublicParams = serverPublicParams;
    }
    createProfileKeyCredentialRequestContext(uuid, profileKey) {
        const random = (0, crypto_1.randomBytes)(Constants_1.RANDOM_LENGTH);
        return this.createProfileKeyCredentialRequestContextWithRandom(random, uuid, profileKey);
    }
    createProfileKeyCredentialRequestContextWithRandom(random, uuid, profileKey) {
        return new ProfileKeyCredentialRequestContext_1.default(Native.ServerPublicParams_CreateProfileKeyCredentialRequestContextDeterministic(this.serverPublicParams.getContents(), random, (0, UUIDUtil_1.fromUUID)(uuid), profileKey.getContents()));
    }
    receiveProfileKeyCredential(profileKeyCredentialRequestContext, profileKeyCredentialResponse) {
        return new ProfileKeyCredential_1.default(Native.ServerPublicParams_ReceiveProfileKeyCredential(this.serverPublicParams.getContents(), profileKeyCredentialRequestContext.getContents(), profileKeyCredentialResponse.getContents()));
    }
    createProfileKeyCredentialPresentation(groupSecretParams, profileKeyCredential) {
        const random = (0, crypto_1.randomBytes)(Constants_1.RANDOM_LENGTH);
        return this.createProfileKeyCredentialPresentationWithRandom(random, groupSecretParams, profileKeyCredential);
    }
    createProfileKeyCredentialPresentationWithRandom(random, groupSecretParams, profileKeyCredential) {
        return new ProfileKeyCredentialPresentation_1.default(Native.ServerPublicParams_CreateProfileKeyCredentialPresentationDeterministic(this.serverPublicParams.getContents(), random, groupSecretParams.getContents(), profileKeyCredential.getContents()));
    }
}
exports.default = ClientZkProfileOperations;
//# sourceMappingURL=ClientZkProfileOperations.js.map