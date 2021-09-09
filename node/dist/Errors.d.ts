import { ProtocolAddress } from './Address';
import * as Native from './Native';
export declare enum ErrorCode {
    Generic = 0,
    DuplicatedMessage = 1,
    SealedSenderSelfSend = 2,
    UntrustedIdentity = 3,
    InvalidRegistrationId = 4
}
export declare class SignalClientErrorBase extends Error {
    readonly code: ErrorCode;
    readonly operation: string;
    readonly _addr?: string | Native.ProtocolAddress;
    constructor(message: string, name: keyof typeof ErrorCode | undefined, operation: string, extraProps?: Record<string, unknown>);
    get addr(): ProtocolAddress | string;
}
export declare type SignalClientErrorCommon = Omit<SignalClientErrorBase, 'addr'>;
export declare type GenericError = SignalClientErrorCommon & {
    code: ErrorCode.Generic;
};
export declare type DuplicatedMessageError = SignalClientErrorCommon & {
    code: ErrorCode.DuplicatedMessage;
};
export declare type SealedSenderSelfSendError = SignalClientErrorCommon & {
    code: ErrorCode.SealedSenderSelfSend;
};
export declare type UntrustedIdentityError = SignalClientErrorCommon & {
    code: ErrorCode.UntrustedIdentity;
    addr: string;
};
export declare type InvalidRegistrationIdError = SignalClientErrorCommon & {
    code: ErrorCode.InvalidRegistrationId;
    addr: ProtocolAddress;
};
export declare type SignalClientError = GenericError | DuplicatedMessageError | SealedSenderSelfSendError | UntrustedIdentityError | InvalidRegistrationIdError;
