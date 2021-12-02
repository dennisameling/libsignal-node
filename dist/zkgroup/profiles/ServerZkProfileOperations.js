"use strict";
//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = require("crypto");
const Native = require("../../../Native");
const Constants_1 = require("../internal/Constants");
const ProfileKeyCredentialResponse_1 = require("./ProfileKeyCredentialResponse");
const UUIDUtil_1 = require("../internal/UUIDUtil");
class ServerZkProfileOperations {
    constructor(serverSecretParams) {
        this.serverSecretParams = serverSecretParams;
    }
    issueProfileKeyCredential(profileKeyCredentialRequest, uuid, profileKeyCommitment) {
        const random = (0, crypto_1.randomBytes)(Constants_1.RANDOM_LENGTH);
        return this.issueProfileKeyCredentialWithRandom(random, profileKeyCredentialRequest, uuid, profileKeyCommitment);
    }
    issueProfileKeyCredentialWithRandom(random, profileKeyCredentialRequest, uuid, profileKeyCommitment) {
        return new ProfileKeyCredentialResponse_1.default(Native.ServerSecretParams_IssueProfileKeyCredentialDeterministic(this.serverSecretParams.getContents(), random, profileKeyCredentialRequest.getContents(), (0, UUIDUtil_1.fromUUID)(uuid), profileKeyCommitment.getContents()));
    }
    verifyProfileKeyCredentialPresentation(groupPublicParams, profileKeyCredentialPresentation) {
        Native.ServerSecretParams_VerifyProfileKeyCredentialPresentation(this.serverSecretParams.getContents(), groupPublicParams.getContents(), profileKeyCredentialPresentation.getContents());
    }
}
exports.default = ServerZkProfileOperations;
//# sourceMappingURL=ServerZkProfileOperations.js.map