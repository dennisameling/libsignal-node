export declare enum ErrorCode {
    Generic = 0,
    UntrustedIdentity = 1,
    SealedSenderSelfSend = 2
}
export declare class SignalClientErrorBase extends Error {
    readonly code: ErrorCode;
    readonly operation: string;
    constructor(message: string, name: keyof typeof ErrorCode | undefined, operation: string, extraProps?: Record<string, unknown>);
}
export declare type GenericError = SignalClientErrorBase & {
    code: ErrorCode.Generic;
};
export declare type UntrustedIdentityError = SignalClientErrorBase & {
    code: ErrorCode.UntrustedIdentity;
    addr: string;
};
export declare type SealedSenderSelfSendError = SignalClientErrorBase & {
    code: ErrorCode.SealedSenderSelfSend;
};
export declare type SignalClientError = GenericError | UntrustedIdentityError | SealedSenderSelfSendError;
