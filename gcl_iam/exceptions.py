#    Copyright 2025 Genesis Corporation.
#
#    All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


from izulu import root


class GenesisCoreLibraryIamError(root.Error):
    __toggles__ = root.Toggles.DEFAULT ^ root.Toggles.FORBID_UNANNOTATED_FIELDS
    __template__ = "Generic Genesis Core Library IAM Error"


class NoIamSessionStored(GenesisCoreLibraryIamError):
    __template__ = "No IAM session stored in context storage"


class CommonForbiddenError(GenesisCoreLibraryIamError):
    __template__ = "Action is forbidden!"


class PolicyNotAuthorized(CommonForbiddenError):
    __template__ = "Policy rule {rule} is disallowed."


class AnotherIamSessionAlreadyStoredError(GenesisCoreLibraryIamError):
    __template__ = "Another IAM session is already stored in context storage"


class IamSessionNotFoundError(GenesisCoreLibraryIamError):
    __template__ = "IAM session not found in context storage"


class CredentialsAreInvalidError(GenesisCoreLibraryIamError):
    __template__ = "The provided credentials are invalid"


class OTPAlreadyEnabledError(CredentialsAreInvalidError):
    __template__ = "OTP is already enabled for this account"


class OTPNotEnabledError(CredentialsAreInvalidError):
    __template__ = "OTP is not enabled for this account"


class InvalidRefreshTokenError(CredentialsAreInvalidError):
    __template__ = "Refresh token has expired or is invalid"


class InvalidAuthTokenError(CredentialsAreInvalidError):
    __template__ = "Auth token has expired or is invalid"


class ClientAuthenticationError(GenesisCoreLibraryIamError):
    __template__ = "Client authentication failed"


class OTPInvalidCodeError(ClientAuthenticationError):
    __template__ = "The provided otp code is invalid"


class IncorrectEncriptionAlgorithmError(GenesisCoreLibraryIamError):
    __template__ = "Incorrect encription algorithm: {algorithm}"


class InvalidGrantTypeError(GenesisCoreLibraryIamError):
    __template__ = "Invalid grant type: {grant_type}"


class Unauthorized(ClientAuthenticationError):
    __template__ = "The request you have made requires authentication."


class Forbidden(CommonForbiddenError):
    __template__ = "The request you have made is forbidden."
