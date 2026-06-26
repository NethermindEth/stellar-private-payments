'use strict';

class ExpiredStateError extends Error {
}
class RestoreFailureError extends Error {
}
class NeedsMoreSignaturesError extends Error {
}
class NoSignatureNeededError extends Error {
}
class NoUnsignedNonInvokerAuthEntriesError extends Error {
}
class NoSignerError extends Error {
}
class NotYetSimulatedError extends Error {
}
class FakeAccountError extends Error {
}
class SimulationFailedError extends Error {
}
class InternalWalletError extends Error {
}
class ExternalServiceError extends Error {
}
class InvalidClientRequestError extends Error {
}
class UserRejectedError extends Error {
}

exports.ExpiredStateError = ExpiredStateError;
exports.ExternalServiceError = ExternalServiceError;
exports.FakeAccountError = FakeAccountError;
exports.InternalWalletError = InternalWalletError;
exports.InvalidClientRequestError = InvalidClientRequestError;
exports.NeedsMoreSignaturesError = NeedsMoreSignaturesError;
exports.NoSignatureNeededError = NoSignatureNeededError;
exports.NoSignerError = NoSignerError;
exports.NoUnsignedNonInvokerAuthEntriesError = NoUnsignedNonInvokerAuthEntriesError;
exports.NotYetSimulatedError = NotYetSimulatedError;
exports.RestoreFailureError = RestoreFailureError;
exports.SimulationFailedError = SimulationFailedError;
exports.UserRejectedError = UserRejectedError;
//# sourceMappingURL=errors.js.map
