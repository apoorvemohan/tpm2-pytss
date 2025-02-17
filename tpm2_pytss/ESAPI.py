"""
SPDX-License-Identifier: BSD-2
"""

from ._libtpm2_pytss import lib

from .types import *

from .utils import _chkrc, TPM2B_pack
from .TCTI import TCTI


def get_ptr(dptr):
    return ffi.gc(dptr[0], lib.Esys_Free)


def get_cdata(value, expected, varname, allow_none=False, *args, **kwargs):
    tname = expected.__name__

    if value is None and allow_none:
        return ffi.NULL
    elif value is None:
        raise TypeError(f"expected {varname} to be {tname}, got None")

    if isinstance(value, ffi.CData):
        tipe = ffi.typeof(value)
        if tipe.kind == "pointer":
            tipe = tipe.item
        classname = fixup_classname(tipe)
        if classname != tname:
            raise TypeError(f"expected {varname} to be {tname}, got {tipe.cname}")
        return value

    vname = type(value).__name__
    parse_method = getattr(expected, "parse", None)
    if isinstance(value, (bytes, str)) and issubclass(expected, TPM2B_SIMPLE_OBJECT):
        bo = expected(value)
        return bo._cdata
    elif isinstance(value, str) and parse_method and callable(parse_method):
        return expected.parse(value, *args, **kwargs)._cdata
    elif issubclass(expected, TPML_OBJECT) and isinstance(value, list):
        return expected(value)._cdata
    elif not isinstance(value, expected):
        raise TypeError(f"expected {varname} to be {tname}, got {vname}")

    return value._cdata


def check_handle_type(handle, varname, expected=None, cls=ESYS_TR):
    if not isinstance(handle, int):
        raise TypeError(
            f"expected {varname} to be type int aka ESYS_TR, got {type(handle)}"
        )

    if expected is not None and handle not in expected:
        if len(expected) > 1:
            msg = f"expected {varname} to be one of {','.join([cls.to_string(x) for x in expected])}, got {cls.to_string(handle)}"
        else:
            msg = f"expected {varname} to be {cls.to_string(expected[0])}, got {cls.to_string(handle)}"

        raise ValueError(msg)


def check_friendly_int(friendly, varname, clazz):

    if not isinstance(friendly, int):
        raise TypeError(f"expected {varname} to be type int, got {type(friendly)}")

    if not clazz.contains(friendly):
        raise ValueError(
            f"expected {varname} value of {friendly} in class {str(clazz)}, however it's not found."
        )


class ESAPI:
    def __init__(self, tcti=None):

        self._tcti = tcti
        tctx = ffi.NULL if tcti is None else tcti._tcti_context

        self.ctx_pp = ffi.new("ESYS_CONTEXT **")
        _chkrc(lib.Esys_Initialize(self.ctx_pp, tctx, ffi.NULL))
        self.ctx = self.ctx_pp[0]

    def __enter__(self):
        return self

    def __exit__(self, _type, value, traceback):
        self.close()

    def close(self):
        lib.Esys_Finalize(self.ctx_pp)
        self.ctx = ffi.NULL

    def GetTcti(self):
        if hasattr(self._tcti, "_tcti_context"):
            return self._tcti
        tctx = ffi.new("TSS2_TCTI_CONTEXT **")
        _chkrc(lib.Esys_GetTcti(self.ctx, tctx))
        return TCTI(tctx[0])

    @property
    def tcti(self):
        return self.GetTcti()

    def tr_from_tpmpublic(
        self,
        handle,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(handle, "handle")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        obj = ffi.new("ESYS_TR *")
        _chkrc(
            lib.Esys_TR_FromTPMPublic(
                self.ctx, handle, session1, session2, session3, obj,
            )
        )
        return obj[0]

    def set_auth(self, esys_tr, auth):

        auth_p = TPM2B_pack(auth, "TPM2B_AUTH")
        _chkrc(lib.Esys_TR_SetAuth(self.ctx, esys_tr, auth_p))

    def tr_get_name(self, handle):

        check_handle_type(handle, "handle")

        name = ffi.new("TPM2B_NAME **")
        _chkrc(lib.Esys_TR_GetName(self.ctx, handle, name))
        return TPM2B_NAME(_cdata=get_ptr(name))

    def startup(self, startup_type):

        check_friendly_int(startup_type, "startup_type", TPM2_SU)

        _chkrc(lib.Esys_Startup(self.ctx, startup_type))

    def shutdown(
        self,
        shutdown_type=TPM2_SU.STATE,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_friendly_int(shutdown_type, "shutdown_type", TPM2_SU)

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(lib.Esys_Shutdown(self.ctx, session1, session2, session3, shutdown_type))

    def self_test(
        self,
        full_test,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        if not isinstance(full_test, bool):
            raise TypeError(
                f"Expected full_test to be type bool, got {type(full_test)}"
            )

        _chkrc(lib.Esys_SelfTest(self.ctx, session1, session2, session3, full_test))

    def incremental_self_test(
        self,
        to_test,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        toTest_cdata = get_cdata(to_test, TPML_ALG, "to_test")

        toDoList = ffi.new("TPML_ALG **")
        _chkrc(
            lib.Esys_IncrementalSelfTest(
                self.ctx, session1, session2, session3, toTest_cdata, toDoList
            )
        )
        return TPML_ALG(get_ptr(toDoList))

    def get_test_result(
        self, session1=ESYS_TR.NONE, session2=ESYS_TR.NONE, session3=ESYS_TR.NONE
    ):

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        outData = ffi.new("TPM2B_MAX_BUFFER **")
        testResult = ffi.new("TPM2_RC *")
        _chkrc(
            lib.Esys_GetTestResult(
                self.ctx, session1, session2, session3, outData, testResult
            )
        )
        return (TPM2B_MAX_BUFFER(get_ptr(outData)), TPM2_RC(testResult[0]))

    def start_auth_session(
        self,
        tpm_key,
        bind,
        nonce_caller,
        session_type,
        symmetric,
        auth_hash,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(tpm_key, "tpm_key")
        check_handle_type(bind, "bind")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        check_friendly_int(session_type, "session_type", TPM2_SE)
        check_friendly_int(auth_hash, "auth_hash", TPM2_ALG)

        nonceCaller_cdata = get_cdata(
            nonce_caller, TPM2B_NONCE, "nonce_caller", allow_none=True
        )
        symmetric_cdata = get_cdata(symmetric, TPMT_SYM_DEF, "symmetric")

        sessionHandle = ffi.new("ESYS_TR *")
        _chkrc(
            lib.Esys_StartAuthSession(
                self.ctx,
                tpm_key,
                bind,
                session1,
                session2,
                session3,
                nonceCaller_cdata,
                session_type,
                symmetric_cdata,
                auth_hash,
                sessionHandle,
            )
        )
        sessionHandleObject = sessionHandle[0]
        return sessionHandleObject

    def trsess_set_attributes(self, session, attributes, mask=0xFF):

        check_handle_type(session, "session")

        if not isinstance(attributes, int):
            raise TypeError(
                f"Expected attributes to be type int, got {type(attributes)}"
            )

        if not isinstance(mask, int):
            raise TypeError(f"Expected mask to be type int, got {type(attributes)}")

        _chkrc(lib.Esys_TRSess_SetAttributes(self.ctx, session, attributes, mask))

    def trsess_get_nonce_tpm(self, session):

        check_handle_type(session, "session")

        nonce = ffi.new("TPM2B_NONCE **")

        _chkrc(lib.Esys_TRSess_GetNonceTPM(self.ctx, session, nonce))

        return TPM2B_NONCE(get_ptr(nonce))

    def policy_restart(
        self,
        session_handle,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(session_handle, "session_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_PolicyRestart(
                self.ctx, session_handle, session1, session2, session3
            )
        )

    def create(
        self,
        parent_handle,
        in_sensitive,
        in_public="rsa2048",
        outside_info=TPM2B_DATA(),
        creation_pcr=TPML_PCR_SELECTION(),
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(parent_handle, "parent_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        inPublic_cdata = get_cdata(in_public, TPM2B_PUBLIC, "in_public")
        inSensitive_cdata = get_cdata(
            in_sensitive, TPM2B_SENSITIVE_CREATE, "in_sensitive"
        )
        outsideInfo_cdata = get_cdata(outside_info, TPM2B_DATA, "outside_info")
        creationPCR_cdata = get_cdata(creation_pcr, TPML_PCR_SELECTION, "creation_pcr")

        outPrivate = ffi.new("TPM2B_PRIVATE **")
        outPublic = ffi.new("TPM2B_PUBLIC **")
        creationData = ffi.new("TPM2B_CREATION_DATA **")
        creationHash = ffi.new("TPM2B_DIGEST **")
        creationTicket = ffi.new("TPMT_TK_CREATION **")
        _chkrc(
            lib.Esys_Create(
                self.ctx,
                parent_handle,
                session1,
                session2,
                session3,
                inSensitive_cdata,
                inPublic_cdata,
                outsideInfo_cdata,
                creationPCR_cdata,
                outPrivate,
                outPublic,
                creationData,
                creationHash,
                creationTicket,
            )
        )
        return (
            TPM2B_PRIVATE(get_ptr(outPrivate)),
            TPM2B_PUBLIC(get_ptr(outPublic)),
            TPM2B_CREATION_DATA(get_ptr(creationData)),
            TPM2B_DIGEST(get_ptr(creationHash)),
            TPMT_TK_CREATION(get_ptr(creationTicket)),
        )

    def load(
        self,
        parent_handle,
        in_private,
        in_public,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(parent_handle, "parent_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        inPublic_cdata = get_cdata(in_public, TPM2B_PUBLIC, "in_public")
        inPrivate_cdata = get_cdata(in_private, TPM2B_PRIVATE, "in_private")

        objectHandle = ffi.new("ESYS_TR *")
        _chkrc(
            lib.Esys_Load(
                self.ctx,
                parent_handle,
                session1,
                session2,
                session3,
                inPrivate_cdata,
                inPublic_cdata,
                objectHandle,
            )
        )
        objectHandleObject = objectHandle[0]
        return objectHandleObject

    def load_external(
        self,
        in_private,
        in_public,
        hierarchy=ESYS_TR.NULL,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_friendly_int(hierarchy, "hierarchy", ESYS_TR)

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        inPrivate_cdata = get_cdata(
            in_private, TPM2B_SENSITIVE, "in_private", allow_none=True
        )

        inPublic_cdata = get_cdata(in_public, TPM2B_PUBLIC, "in_public")

        objectHandle = ffi.new("ESYS_TR *")
        _chkrc(
            lib.Esys_LoadExternal(
                self.ctx,
                session1,
                session2,
                session3,
                inPrivate_cdata,
                inPublic_cdata,
                hierarchy,
                objectHandle,
            )
        )
        objectHandleObject = objectHandle[0]
        return objectHandleObject

    def read_public(
        self,
        object_handle,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(object_handle, "object_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        outPublic = ffi.new("TPM2B_PUBLIC **")
        name = ffi.new("TPM2B_NAME **")
        qualifiedName = ffi.new("TPM2B_NAME **")
        _chkrc(
            lib.Esys_ReadPublic(
                self.ctx,
                object_handle,
                session1,
                session2,
                session3,
                outPublic,
                name,
                qualifiedName,
            )
        )
        return (
            TPM2B_PUBLIC(get_ptr(outPublic)),
            TPM2B_NAME(get_ptr(name)),
            TPM2B_NAME(get_ptr(qualifiedName)),
        )

    def activate_credential(
        self,
        activate_handle,
        key_handle,
        credential_blob,
        secret,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.PASSWORD,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(activate_handle, "activate_handle")
        check_handle_type(key_handle, "key_handle")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        credentialBlob_cdata = get_cdata(
            credential_blob, TPM2B_ID_OBJECT, "credential_blob"
        )
        secret_cdata = get_cdata(secret, TPM2B_ENCRYPTED_SECRET, "secret")

        certInfo = ffi.new("TPM2B_DIGEST **")
        _chkrc(
            lib.Esys_ActivateCredential(
                self.ctx,
                activate_handle,
                key_handle,
                session1,
                session2,
                session3,
                credentialBlob_cdata,
                secret_cdata,
                certInfo,
            )
        )
        return TPM2B_DIGEST(get_ptr(certInfo))

    def make_credential(
        self,
        handle,
        credential,
        object_name,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(handle, "handle")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        credential_cdata = get_cdata(credential, TPM2B_DIGEST, "credential")
        objectName_cdata = get_cdata(object_name, TPM2B_NAME, "object_name")

        credentialBlob = ffi.new("TPM2B_ID_OBJECT **")
        secret = ffi.new("TPM2B_ENCRYPTED_SECRET **")
        _chkrc(
            lib.Esys_MakeCredential(
                self.ctx,
                handle,
                session1,
                session2,
                session3,
                credential_cdata,
                objectName_cdata,
                credentialBlob,
                secret,
            )
        )
        return (
            TPM2B_ID_OBJECT(get_ptr(credentialBlob)),
            TPM2B_ENCRYPTED_SECRET(get_ptr(secret)),
        )

    def unseal(
        self,
        item_handle,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(item_handle, "item_handle")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        outData = ffi.new("TPM2B_SENSITIVE_DATA **")
        _chkrc(
            lib.Esys_Unseal(
                self.ctx, item_handle, session1, session2, session3, outData
            )
        )
        return TPM2B_SENSITIVE_DATA(get_ptr(outData))

    def object_change_auth(
        self,
        object_handle,
        parent_handle,
        new_auth,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(object_handle, "object_handle")
        check_handle_type(parent_handle, "parent_handle")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        newAuth_cdata = get_cdata(new_auth, TPM2B_AUTH, "new_auth")

        outPrivate = ffi.new("TPM2B_PRIVATE **")
        _chkrc(
            lib.Esys_ObjectChangeAuth(
                self.ctx,
                object_handle,
                parent_handle,
                session1,
                session2,
                session3,
                newAuth_cdata,
                outPrivate,
            )
        )
        return TPM2B_PRIVATE(get_ptr(outPrivate))

    def create_loaded(
        self,
        parent_handle,
        in_sensitive,
        in_public="rsa2048",
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(parent_handle, "parent_handle")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        if isinstance(in_public, str):
            in_public = TPM2B_TEMPLATE(TPMT_PUBLIC.parse(in_public).Marshal())

        inSensitive_cdata = get_cdata(
            in_sensitive, TPM2B_SENSITIVE_CREATE, "in_sensitive"
        )
        inPublic_cdata = get_cdata(in_public, TPM2B_TEMPLATE, "in_public")

        objectHandle = ffi.new("ESYS_TR *")
        outPrivate = ffi.new("TPM2B_PRIVATE **")
        outPublic = ffi.new("TPM2B_PUBLIC **")
        _chkrc(
            lib.Esys_CreateLoaded(
                self.ctx,
                parent_handle,
                session1,
                session2,
                session3,
                inSensitive_cdata,
                inPublic_cdata,
                objectHandle,
                outPrivate,
                outPublic,
            )
        )
        objectHandleObject = objectHandle[0]
        return (
            objectHandleObject,
            TPM2B_PRIVATE(get_ptr(outPrivate)),
            TPM2B_PUBLIC(get_ptr(outPublic)),
        )

    def duplicate(
        self,
        object_handle,
        new_parent_handle,
        encryption_key_in,
        symmetric_alg,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(object_handle, "object_handle")
        check_handle_type(new_parent_handle, "new_parent_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        encryptionKeyIn_cdata = get_cdata(
            encryption_key_in, TPM2B_DATA, "encryption_key_in", allow_none=True
        )
        symmetricAlg_cdata = get_cdata(
            symmetric_alg, TPMT_SYM_DEF_OBJECT, "symmetric_alg"
        )

        encryptionKeyOut = ffi.new("TPM2B_DATA **")
        duplicate = ffi.new("TPM2B_PRIVATE **")
        outSymSeed = ffi.new("TPM2B_ENCRYPTED_SECRET **")
        _chkrc(
            lib.Esys_Duplicate(
                self.ctx,
                object_handle,
                new_parent_handle,
                session1,
                session2,
                session3,
                encryptionKeyIn_cdata,
                symmetricAlg_cdata,
                encryptionKeyOut,
                duplicate,
                outSymSeed,
            )
        )

        return (
            TPM2B_DATA(get_ptr(encryptionKeyOut)),
            TPM2B_PRIVATE(get_ptr(duplicate)),
            TPM2B_ENCRYPTED_SECRET(get_ptr(outSymSeed)),
        )

    def rewrap(
        self,
        old_parent,
        new_parent,
        in_duplicate,
        name,
        in_sym_seed,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(old_parent, "old_parent")
        check_handle_type(new_parent, "new_parent")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        inDuplicate_cdata = get_cdata(in_duplicate, TPM2B_PRIVATE, "in_duplicate")

        inSymSeed_cdata = get_cdata(in_sym_seed, TPM2B_ENCRYPTED_SECRET, "in_sym_seed")

        name_cdata = get_cdata(name, TPM2B_NAME, "name")

        outDuplicate = ffi.new("TPM2B_PRIVATE **")
        outSymSeed = ffi.new("TPM2B_ENCRYPTED_SECRET **")
        _chkrc(
            lib.Esys_Rewrap(
                self.ctx,
                old_parent,
                new_parent,
                session1,
                session2,
                session3,
                inDuplicate_cdata,
                name_cdata,
                inSymSeed_cdata,
                outDuplicate,
                outSymSeed,
            )
        )
        return (
            TPM2B_PRIVATE(get_ptr(outDuplicate)),
            TPM2B_ENCRYPTED_SECRET(get_ptr(outSymSeed)),
        )

    def import_(
        self,
        parent_handle,
        encryption_key,
        object_public,
        duplicate,
        in_sym_seed,
        symmetricAlg,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(parent_handle, "parent_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        encryptionKey_cdata = get_cdata(encryption_key, TPM2B_DATA, "encryption_key")

        objectPublic_cdata = get_cdata(object_public, TPM2B_PUBLIC, "object_public")

        duplicate_cdata = get_cdata(duplicate, TPM2B_PRIVATE, "duplicate")

        inSymSeed_cdata = get_cdata(in_sym_seed, TPM2B_ENCRYPTED_SECRET, "in_sym_seed")

        symmetricAlg_cdata = get_cdata(
            symmetricAlg, TPMT_SYM_DEF_OBJECT, "symmetricAlg"
        )

        outPrivate = ffi.new("TPM2B_PRIVATE **")
        _chkrc(
            lib.Esys_Import(
                self.ctx,
                parent_handle,
                session1,
                session2,
                session3,
                encryptionKey_cdata,
                objectPublic_cdata,
                duplicate_cdata,
                inSymSeed_cdata,
                symmetricAlg_cdata,
                outPrivate,
            )
        )
        return TPM2B_PRIVATE(get_ptr(outPrivate))

    def rsa_encrypt(
        self,
        key_handle,
        message,
        in_scheme,
        label=None,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(key_handle, "key_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        inScheme_cdata = get_cdata(in_scheme, TPMT_RSA_DECRYPT, "in_scheme")
        message_cdata = get_cdata(message, TPM2B_PUBLIC_KEY_RSA, "message")
        label_cdata = get_cdata(label, TPM2B_DATA, "label", allow_none=True)

        outData = ffi.new("TPM2B_PUBLIC_KEY_RSA **")
        _chkrc(
            lib.Esys_RSA_Encrypt(
                self.ctx,
                key_handle,
                session1,
                session2,
                session3,
                message_cdata,
                inScheme_cdata,
                label_cdata,
                outData,
            )
        )
        return TPM2B_PUBLIC_KEY_RSA(get_ptr(outData))

    def rsa_decrypt(
        self,
        key_handle,
        cipher_text,
        in_scheme,
        label=None,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(key_handle, "key_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        inScheme_cdata = get_cdata(in_scheme, TPMT_RSA_DECRYPT, "in_scheme")
        cipherText_cdata = get_cdata(cipher_text, TPM2B_PUBLIC_KEY_RSA, "cipher_text")
        label_cdata = get_cdata(label, TPM2B_DATA, "label", allow_none=True)

        message = ffi.new("TPM2B_PUBLIC_KEY_RSA **")
        _chkrc(
            lib.Esys_RSA_Decrypt(
                self.ctx,
                key_handle,
                session1,
                session2,
                session3,
                cipherText_cdata,
                inScheme_cdata,
                label_cdata,
                message,
            )
        )
        return TPM2B_PUBLIC_KEY_RSA(get_ptr(message))

    def ecdh_key_gen(
        self,
        key_handle,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(key_handle, "key_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        zPoint = ffi.new("TPM2B_ECC_POINT **")
        pubPoint = ffi.new("TPM2B_ECC_POINT **")
        _chkrc(
            lib.Esys_ECDH_KeyGen(
                self.ctx, key_handle, session1, session2, session3, zPoint, pubPoint
            )
        )
        return (TPM2B_ECC_POINT(get_ptr(zPoint)), TPM2B_ECC_POINT(get_ptr(pubPoint)))

    def ecdh_zgen(
        self,
        key_handle,
        in_point,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(key_handle, "key_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        inPoint_cdata = get_cdata(in_point, TPM2B_ECC_POINT, "in_point")

        outPoint = ffi.new("TPM2B_ECC_POINT **")
        _chkrc(
            lib.Esys_ECDH_ZGen(
                self.ctx,
                key_handle,
                session1,
                session2,
                session3,
                inPoint_cdata,
                outPoint,
            )
        )
        return TPM2B_ECC_POINT(get_ptr(outPoint))

    def ecc_parameters(
        self,
        curve_id,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_friendly_int(curve_id, "curve_id", TPM2_ECC_CURVE)

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        parameters = ffi.new("TPMS_ALGORITHM_DETAIL_ECC **")
        _chkrc(
            lib.Esys_ECC_Parameters(
                self.ctx, session1, session2, session3, curve_id, parameters
            )
        )
        return TPMS_ALGORITHM_DETAIL_ECC(get_ptr(parameters))

    def zgen_2_phase(
        self,
        key_a,
        in_qs_b,
        in_qe_b,
        in_scheme,
        counter,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(session1, "key_a")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        check_friendly_int(in_scheme, "in_scheme", TPM2_ALG)

        if not isinstance(counter, int):
            raise TypeError(f"Expected counter to be type int, got {type(counter)}")

        if counter < 0 or counter > 65535:
            raise ValueError(
                f"Expected counter to be in range of uint16_t, got {counter}"
            )

        inQsB_cdata = get_cdata(in_qs_b, TPM2B_ECC_POINT, "in_qs_b")
        inQeB_cdata = get_cdata(in_qe_b, TPM2B_ECC_POINT, "in_qe_b")

        outZ1 = ffi.new("TPM2B_ECC_POINT **")
        outZ2 = ffi.new("TPM2B_ECC_POINT **")
        _chkrc(
            lib.Esys_ZGen_2Phase(
                self.ctx,
                key_a,
                session1,
                session2,
                session3,
                inQsB_cdata,
                inQeB_cdata,
                in_scheme,
                counter,
                outZ1,
                outZ2,
            )
        )

        return (TPM2B_ECC_POINT(get_ptr(outZ1)), TPM2B_ECC_POINT(get_ptr(outZ2)))

    def encrypt_decrypt(
        self,
        key_handle,
        decrypt,
        mode,
        iv_in,
        in_data,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(key_handle, "key_handle")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        check_friendly_int(mode, "mode", TPM2_ALG)

        ivIn_cdata = get_cdata(iv_in, TPM2B_IV, "iv_in")
        inData_cdata = get_cdata(in_data, TPM2B_MAX_BUFFER, "in_data")

        if not isinstance(decrypt, bool):
            raise TypeError(f"Expected decrypt to be type bool, got {type(decrypt)}")

        outData = ffi.new("TPM2B_MAX_BUFFER **")
        ivOut = ffi.new("TPM2B_IV **")
        _chkrc(
            lib.Esys_EncryptDecrypt(
                self.ctx,
                key_handle,
                session1,
                session2,
                session3,
                decrypt,
                mode,
                ivIn_cdata,
                inData_cdata,
                outData,
                ivOut,
            )
        )
        return (TPM2B_MAX_BUFFER(get_ptr(outData)), TPM2B_IV(get_ptr(ivOut)))

    def encrypt_decrypt_2(
        self,
        key_handle,
        decrypt,
        mode,
        iv_in,
        in_data,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(key_handle, "key_handle")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        check_friendly_int(mode, "mode", TPM2_ALG)

        ivIn_cdata = get_cdata(iv_in, TPM2B_IV, "iv_in")
        inData_cdata = get_cdata(in_data, TPM2B_MAX_BUFFER, "in_data")

        if not isinstance(decrypt, bool):
            raise TypeError("Expected decrypt to be type bool, got {type(decrypt)}")

        outData = ffi.new("TPM2B_MAX_BUFFER **")
        ivOut = ffi.new("TPM2B_IV **")
        _chkrc(
            lib.Esys_EncryptDecrypt2(
                self.ctx,
                key_handle,
                session1,
                session2,
                session3,
                inData_cdata,
                decrypt,
                mode,
                ivIn_cdata,
                outData,
                ivOut,
            )
        )
        return (TPM2B_MAX_BUFFER(get_ptr(outData)), TPM2B_IV(get_ptr(ivOut)))

    def hash(
        self,
        data,
        hash_alg,
        hierarchy=ESYS_TR.OWNER,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        check_friendly_int(hash_alg, "hash_alg", TPM2_ALG)

        data_cdata = get_cdata(data, TPM2B_MAX_BUFFER, "data")

        outHash = ffi.new("TPM2B_DIGEST **")
        validation = ffi.new("TPMT_TK_HASHCHECK **")
        _chkrc(
            lib.Esys_Hash(
                self.ctx,
                session1,
                session2,
                session3,
                data_cdata,
                hash_alg,
                hierarchy,
                outHash,
                validation,
            )
        )
        return (TPM2B_DIGEST(get_ptr(outHash)), TPMT_TK_HASHCHECK(get_ptr(validation)))

    def hmac(
        self,
        handle,
        buffer,
        hash_alg,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(handle, "handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        check_friendly_int(hash_alg, "hash_alg", TPM2_ALG)

        buffer_cdata = get_cdata(buffer, TPM2B_MAX_BUFFER, "buffer")

        outHMAC = ffi.new("TPM2B_DIGEST **")
        _chkrc(
            lib.Esys_HMAC(
                self.ctx,
                handle,
                session1,
                session2,
                session3,
                buffer_cdata,
                hash_alg,
                outHMAC,
            )
        )
        return TPM2B_DIGEST(get_ptr(outHMAC))

    def get_random(
        self,
        bytes_requested,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        if not isinstance(bytes_requested, int):
            raise TypeError(
                f"Expected bytes_requested type to be int, got {type(bytes_requested)}"
            )

        randomBytes = ffi.new("TPM2B_DIGEST **")
        _chkrc(
            lib.Esys_GetRandom(
                self.ctx, session1, session2, session3, bytes_requested, randomBytes
            )
        )

        return TPM2B_DIGEST(get_ptr(randomBytes))

    def stir_random(
        self,
        in_data,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        inData_cdata = get_cdata(in_data, TPM2B_SENSITIVE_DATA, "in_data")

        _chkrc(
            lib.Esys_StirRandom(self.ctx, session1, session2, session3, inData_cdata)
        )

    def hmac_start(
        self,
        handle,
        auth,
        hash_alg,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(handle, "handle")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        check_friendly_int(hash_alg, "hash_alg", TPM2_ALG)

        if auth is None:
            auth = TPM2B_AUTH()

        auth_cdata = get_cdata(auth, TPM2B_AUTH, "auth")

        sequenceHandle = ffi.new("ESYS_TR *")
        _chkrc(
            lib.Esys_HMAC_Start(
                self.ctx,
                handle,
                session1,
                session2,
                session3,
                auth_cdata,
                hash_alg,
                sequenceHandle,
            )
        )
        sequenceHandleObject = sequenceHandle[0]
        return sequenceHandleObject

    def hash_sequence_start(
        self,
        auth,
        hash_alg,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        check_friendly_int(hash_alg, "hash_alg", TPM2_ALG)

        if auth is None:
            auth = TPM2B_AUTH()

        auth_cdata = get_cdata(auth, TPM2B_AUTH, "auth")

        sequenceHandle = ffi.new("ESYS_TR *")
        _chkrc(
            lib.Esys_HashSequenceStart(
                self.ctx,
                session1,
                session2,
                session3,
                auth_cdata,
                hash_alg,
                sequenceHandle,
            )
        )
        sequenceHandleObject = sequenceHandle[0]
        return sequenceHandleObject

    def sequence_update(
        self,
        sequence_handle,
        buffer,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(sequence_handle, "sequence_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        buffer_cdata = get_cdata(buffer, TPM2B_MAX_BUFFER, "buffer", allow_none=True)

        _chkrc(
            lib.Esys_SequenceUpdate(
                self.ctx, sequence_handle, session1, session2, session3, buffer_cdata
            )
        )

    def sequence_complete(
        self,
        sequence_handle,
        buffer,
        hierarchy=ESYS_TR.OWNER,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(sequence_handle, "sequence_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        check_friendly_int(hierarchy, "hierarchy", ESYS_TR)

        buffer_cdata = get_cdata(buffer, TPM2B_MAX_BUFFER, "buffer", allow_none=True)

        result = ffi.new("TPM2B_DIGEST **")
        validation = ffi.new("TPMT_TK_HASHCHECK **")
        _chkrc(
            lib.Esys_SequenceComplete(
                self.ctx,
                sequence_handle,
                session1,
                session2,
                session3,
                buffer_cdata,
                hierarchy,
                result,
                validation,
            )
        )

        return (TPM2B_DIGEST(get_ptr(result)), TPMT_TK_HASHCHECK(get_ptr(validation)))

    def event_sequence_complete(
        self,
        pcr_handle,
        sequence_handle,
        buffer,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.PASSWORD,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(sequence_handle, "sequence_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        check_friendly_int(pcr_handle, "pcr_handle", ESYS_TR)

        buffer_cdata = get_cdata(buffer, TPM2B_MAX_BUFFER, "buffer", allow_none=True)

        results = ffi.new("TPML_DIGEST_VALUES **")
        _chkrc(
            lib.Esys_EventSequenceComplete(
                self.ctx,
                pcr_handle,
                sequence_handle,
                session1,
                session2,
                session3,
                buffer_cdata,
                results,
            )
        )
        return TPML_DIGEST_VALUES(get_ptr(results))

    def certify(
        self,
        object_handle,
        sign_handle,
        qualifying_data,
        in_scheme,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.PASSWORD,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(object_handle, "object_handle")
        check_handle_type(sign_handle, "sign_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        qualifyingData_cdata = get_cdata(qualifying_data, TPM2B_DATA, "qualifying_data")
        inScheme_cdata = get_cdata(in_scheme, TPMT_SIG_SCHEME, "in_scheme")

        certifyInfo = ffi.new("TPM2B_ATTEST **")
        signature = ffi.new("TPMT_SIGNATURE **")
        _chkrc(
            lib.Esys_Certify(
                self.ctx,
                object_handle,
                sign_handle,
                session1,
                session2,
                session3,
                qualifyingData_cdata,
                inScheme_cdata,
                certifyInfo,
                signature,
            )
        )
        return (TPM2B_ATTEST(get_ptr(certifyInfo)), TPMT_SIGNATURE(get_ptr(signature)))

    def certify_creation(
        self,
        sign_handle,
        object_handle,
        qualifying_data,
        creation_hash,
        in_scheme,
        creation_ticket,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(object_handle, "object_handle")
        check_handle_type(sign_handle, "sign_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        qualifyingData_cdata = get_cdata(qualifying_data, TPM2B_DATA, "qualifying_data")
        inScheme_cdata = get_cdata(in_scheme, TPMT_SIG_SCHEME, "in_scheme")
        creationHash_cdata = get_cdata(creation_hash, TPM2B_DIGEST, "creation_hash")
        creationTicket_cdata = get_cdata(
            creation_ticket, TPMT_TK_CREATION, "creation_ticket"
        )

        certifyInfo = ffi.new("TPM2B_ATTEST **")
        signature = ffi.new("TPMT_SIGNATURE **")
        _chkrc(
            lib.Esys_CertifyCreation(
                self.ctx,
                sign_handle,
                object_handle,
                session1,
                session2,
                session3,
                qualifyingData_cdata,
                creationHash_cdata,
                inScheme_cdata,
                creationTicket_cdata,
                certifyInfo,
                signature,
            )
        )
        return (TPM2B_ATTEST(get_ptr(certifyInfo)), TPMT_SIGNATURE(get_ptr(signature)))

    def quote(
        self,
        sign_handle,
        pcr_select,
        qualifying_data,
        in_scheme=TPMT_SIG_SCHEME(scheme=TPM2_ALG.NULL),
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(sign_handle, "sign_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        qualifyingData_cdata = get_cdata(qualifying_data, TPM2B_DATA, "qualifying_data")

        inScheme_cdata = get_cdata(in_scheme, TPMT_SIG_SCHEME, "in_scheme")

        PCRselect_cdata = get_cdata(pcr_select, TPML_PCR_SELECTION, "pcr_select")

        quoted = ffi.new("TPM2B_ATTEST **")
        signature = ffi.new("TPMT_SIGNATURE **")
        _chkrc(
            lib.Esys_Quote(
                self.ctx,
                sign_handle,
                session1,
                session2,
                session3,
                qualifyingData_cdata,
                inScheme_cdata,
                PCRselect_cdata,
                quoted,
                signature,
            )
        )
        return (TPM2B_ATTEST(get_ptr(quoted)), TPMT_SIGNATURE(get_ptr(signature)))

    def get_session_audit_digest(
        self,
        sign_handle,
        session_handle,
        qualifying_data,
        in_scheme=TPMT_SIG_SCHEME(scheme=TPM2_ALG.NULL),
        privacy_admin_handle=ESYS_TR.RH_ENDORSEMENT,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.PASSWORD,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(session_handle, "session_handle")
        check_handle_type(
            privacy_admin_handle,
            "privacy_admin_handle",
            expected=[ESYS_TR.RH_ENDORSEMENT],
        )
        check_handle_type(sign_handle, "sign_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        qualifyingData_cdata = get_cdata(
            qualifying_data, TPM2B_DATA, "qualifying_data", allow_none=True
        )

        inScheme_cdata = get_cdata(in_scheme, TPMT_SIG_SCHEME, "in_scheme")

        auditInfo = ffi.new("TPM2B_ATTEST **")
        signature = ffi.new("TPMT_SIGNATURE **")
        _chkrc(
            lib.Esys_GetSessionAuditDigest(
                self.ctx,
                privacy_admin_handle,
                sign_handle,
                session_handle,
                session1,
                session2,
                session3,
                qualifyingData_cdata,
                inScheme_cdata,
                auditInfo,
                signature,
            )
        )
        return (TPM2B_ATTEST(get_ptr(auditInfo)), TPMT_SIGNATURE(get_ptr(signature)))

    def get_command_audit_digest(
        self,
        sign_handle,
        qualifying_data,
        in_scheme=TPMT_SIG_SCHEME(scheme=TPM2_ALG.NULL),
        privacy_handle=ESYS_TR.RH_ENDORSEMENT,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.PASSWORD,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(
            privacy_handle, "privacy_handle", expected=[ESYS_TR.RH_ENDORSEMENT]
        )
        check_handle_type(sign_handle, "sign_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        qualifyingData_cdata = get_cdata(
            qualifying_data, TPM2B_DATA, "qualifying_data", allow_none=True
        )

        inScheme_cdata = get_cdata(in_scheme, TPMT_SIG_SCHEME, "in_scheme")

        auditInfo = ffi.new("TPM2B_ATTEST **")
        signature = ffi.new("TPMT_SIGNATURE **")
        _chkrc(
            lib.Esys_GetCommandAuditDigest(
                self.ctx,
                privacy_handle,
                sign_handle,
                session1,
                session2,
                session3,
                qualifyingData_cdata,
                inScheme_cdata,
                auditInfo,
                signature,
            )
        )
        return (TPM2B_ATTEST(get_ptr(auditInfo)), TPMT_SIGNATURE(get_ptr(signature)))

    def get_time(
        self,
        sign_handle,
        qualifying_data,
        in_scheme=TPMT_SIG_SCHEME(scheme=TPM2_ALG.NULL),
        privacy_admin_handle=ESYS_TR.RH_ENDORSEMENT,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.PASSWORD,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(
            privacy_admin_handle, "privacy_admin_handle", expected=[ESYS_TR.ENDORSEMENT]
        )
        check_handle_type(sign_handle, "sign_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        qualifyingData_cdata = get_cdata(
            qualifying_data, TPM2B_DATA, "qualifying_data", allow_none=True
        )

        inScheme_cdata = get_cdata(in_scheme, TPMT_SIG_SCHEME, "in_scheme")

        timeInfo = ffi.new("TPM2B_ATTEST **")
        signature = ffi.new("TPMT_SIGNATURE **")
        _chkrc(
            lib.Esys_GetTime(
                self.ctx,
                privacy_admin_handle,
                sign_handle,
                session1,
                session2,
                session3,
                qualifyingData_cdata,
                inScheme_cdata,
                timeInfo,
                signature,
            )
        )
        return (TPM2B_ATTEST(get_ptr(timeInfo)), TPMT_SIGNATURE(get_ptr(signature)))

    def commit(
        self,
        sign_handle,
        p1,
        s2,
        y2,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(sign_handle, "sign_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        P1_cdata = get_cdata(p1, TPM2B_ECC_POINT, "p1")
        s2_cdata = get_cdata(s2, TPM2B_SENSITIVE_DATA, "s2")
        y2_cdata = get_cdata(y2, TPM2B_ECC_PARAMETER, "y2")

        K = ffi.new("TPM2B_ECC_POINT **")
        L = ffi.new("TPM2B_ECC_POINT **")
        E = ffi.new("TPM2B_ECC_POINT **")
        counter = ffi.new("UINT16 *")
        _chkrc(
            lib.Esys_Commit(
                self.ctx,
                sign_handle,
                session1,
                session2,
                session3,
                P1_cdata,
                s2_cdata,
                y2_cdata,
                K,
                L,
                E,
                counter,
            )
        )
        return (
            TPM2B_ECC_POINT(get_ptr(K)),
            TPM2B_ECC_POINT(get_ptr(L)),
            TPM2B_ECC_POINT(get_ptr(E)),
            counter[0],
        )

    def ec_ephemeral(
        self,
        curve_id,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        Q = ffi.new("TPM2B_ECC_POINT **")
        counter = ffi.new("UINT16 *")
        _chkrc(
            lib.Esys_EC_Ephemeral(
                self.ctx, session1, session2, session3, curve_id, Q, counter
            )
        )
        return (TPM2B_ECC_POINT(get_ptr(Q)), counter[0])

    def verify_signature(
        self,
        key_handle,
        digest,
        signature,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(key_handle, "key_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        digest_cdata = get_cdata(digest, TPM2B_DIGEST, "digest")
        signature_cdata = get_cdata(signature, TPMT_SIGNATURE, "signature")

        validation = ffi.new("TPMT_TK_VERIFIED **")
        _chkrc(
            lib.Esys_VerifySignature(
                self.ctx,
                key_handle,
                session1,
                session2,
                session3,
                digest_cdata,
                signature_cdata,
                validation,
            )
        )
        return TPMT_TK_VERIFIED(get_ptr(validation))

    def sign(
        self,
        key_handle,
        digest,
        in_scheme,
        validation,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(key_handle, "key_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        digest_cdata = get_cdata(digest, TPM2B_DIGEST, "digest")
        inScheme_cdata = get_cdata(in_scheme, TPMT_SIG_SCHEME, "in_scheme")
        validation_cdata = get_cdata(validation, TPMT_TK_HASHCHECK, "validation")

        signature = ffi.new("TPMT_SIGNATURE **")
        _chkrc(
            lib.Esys_Sign(
                self.ctx,
                key_handle,
                session1,
                session2,
                session3,
                digest_cdata,
                inScheme_cdata,
                validation_cdata,
                signature,
            )
        )
        return TPMT_SIGNATURE(get_ptr(signature))

    def set_command_code_audit_status(
        self,
        audit_alg,
        set_list,
        clear_list,
        auth=ESYS_TR.OWNER,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(auth, "auth", expected=[ESYS_TR.OWNER, ESYS_TR.PLATFORM])

        check_friendly_int(audit_alg, "audit_alg", TPM2_ALG)

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        setList_cdata = get_cdata(set_list, TPML_CC, "set_list")
        clearList_cdata = get_cdata(clear_list, TPML_CC, "digest")

        _chkrc(
            lib.Esys_SetCommandCodeAuditStatus(
                self.ctx,
                auth,
                session1,
                session2,
                session3,
                audit_alg,
                setList_cdata,
                clearList_cdata,
            )
        )

    def pcr_extend(
        self,
        pcr_handle,
        digests,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(pcr_handle, "pcr_handle")

        digests_cdata = get_cdata(digests, TPML_DIGEST_VALUES, "digests")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_PCR_Extend(
                self.ctx, pcr_handle, session1, session2, session3, digests_cdata
            )
        )

    def pcr_event(
        self,
        pcr_handle,
        event_data,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        check_handle_type(pcr_handle, "pcr_handle")

        eventData_cdata = get_cdata(event_data, TPM2B_EVENT, "event_data")

        digests = ffi.new("TPML_DIGEST_VALUES **")
        _chkrc(
            lib.Esys_PCR_Event(
                self.ctx,
                pcr_handle,
                session1,
                session2,
                session3,
                eventData_cdata,
                digests,
            )
        )
        return TPML_DIGEST_VALUES(get_ptr(digests))

    def pcr_read(
        self,
        pcr_selection_in,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        pcrSelectionIn_cdata = get_cdata(
            pcr_selection_in, TPML_PCR_SELECTION, "pcr_selection_in"
        )

        pcrUpdateCounter = ffi.new("UINT32 *")
        pcrSelectionOut = ffi.new("TPML_PCR_SELECTION **")
        pcrValues = ffi.new("TPML_DIGEST **")
        _chkrc(
            lib.Esys_PCR_Read(
                self.ctx,
                session1,
                session2,
                session3,
                pcrSelectionIn_cdata,
                pcrUpdateCounter,
                pcrSelectionOut,
                pcrValues,
            )
        )

        return (
            pcrUpdateCounter[0],
            TPML_PCR_SELECTION(_cdata=get_ptr(pcrSelectionOut)),
            TPML_DIGEST(_cdata=get_ptr(pcrValues)),
        )

    def pcr_allocate(
        self,
        pcr_allocation,
        auth_handle=ESYS_TR.PLATFORM,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(auth_handle, "auth_handle", expected=[ESYS_TR.PLATFORM])
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        pcrAllocation_cdata = get_cdata(
            pcr_allocation, TPML_PCR_SELECTION, "pcr_allocation"
        )

        allocationSuccess = ffi.new("TPMI_YES_NO *")
        maxPCR = ffi.new("UINT32 *")
        sizeNeeded = ffi.new("UINT32 *")
        sizeAvailable = ffi.new("UINT32 *")
        _chkrc(
            lib.Esys_PCR_Allocate(
                self.ctx,
                auth_handle,
                session1,
                session2,
                session3,
                pcrAllocation_cdata,
                allocationSuccess,
                maxPCR,
                sizeNeeded,
                sizeAvailable,
            )
        )
        return (bool(allocationSuccess[0]), maxPCR[0], sizeNeeded[0], sizeAvailable[0])

    def pcr_set_auth_policy(
        self,
        auth_policy,
        hash_alg,
        pcr_num,
        auth_handle=ESYS_TR.PLATFORM,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(auth_handle, "auth_handle", expected=[ESYS_TR.PLATFORM])

        check_friendly_int(hash_alg, "hash_alg", TPM2_ALG)
        check_friendly_int(pcr_num, "pcr_num", ESYS_TR)

        authPolicy_cdata = get_cdata(auth_policy, TPM2B_DIGEST, "auth_policy")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_PCR_SetAuthPolicy(
                self.ctx,
                auth_handle,
                session1,
                session2,
                session3,
                authPolicy_cdata,
                hash_alg,
                pcr_num,
            )
        )

    def pcr_set_auth_value(
        self,
        pcr_handle,
        auth,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_friendly_int(pcr_handle, "pcr_handle", ESYS_TR)

        auth_cdata = get_cdata(auth, TPM2B_DIGEST, "auth")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_PCR_SetAuthValue(
                self.ctx, pcr_handle, session1, session2, session3, auth_cdata
            )
        )

    def pcr_reset(
        self,
        pcr_handle,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_friendly_int(pcr_handle, "pcr_handle", ESYS_TR)

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(lib.Esys_PCR_Reset(self.ctx, pcr_handle, session1, session2, session3))

    def policy_signed(
        self,
        auth_object,
        policy_session,
        nonce_tpm,
        cp_hash_a,
        policy_ref,
        expiration,
        auth,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(auth_object, "auth_object")

        check_handle_type(policy_session, "policy_session")

        if not isinstance(expiration, int):
            raise TypeError(
                f"expected expiration to be type int, got {type(expiration)}"
            )

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        nonceTPM_cdata = get_cdata(nonce_tpm, TPM2B_NONCE, "nonce_tpm")
        cpHashA_cdata = get_cdata(cp_hash_a, TPM2B_DIGEST, "cp_hash_a")
        policyRef_cdata = get_cdata(policy_ref, TPM2B_NONCE, "policy_ref")
        auth_cdata = get_cdata(auth, TPMT_SIGNATURE, "auth")

        timeout = ffi.new("TPM2B_TIMEOUT **")
        policyTicket = ffi.new("TPMT_TK_AUTH **")
        _chkrc(
            lib.Esys_PolicySigned(
                self.ctx,
                auth_object,
                policy_session,
                session1,
                session2,
                session3,
                nonceTPM_cdata,
                cpHashA_cdata,
                policyRef_cdata,
                expiration,
                auth_cdata,
                timeout,
                policyTicket,
            )
        )
        return (TPM2B_TIMEOUT(get_ptr(timeout)), TPMT_TK_AUTH(get_ptr(policyTicket)))

    def policy_secret(
        self,
        auth_handle,
        policy_session,
        nonce_tpm,
        cp_hash_a,
        policy_ref,
        expiration,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(policy_session, "policy_session")

        if not isinstance(expiration, int):
            raise TypeError(
                f"expected expiration to be type int, got {type(expiration)}"
            )

        check_friendly_int(auth_handle, "auth_handle", ESYS_TR)

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        nonceTPM_cdata = get_cdata(nonce_tpm, TPM2B_NONCE, "nonce_tpm")
        cpHashA_cdata = get_cdata(cp_hash_a, TPM2B_DIGEST, "cp_hash_a")
        policyRef_cdata = get_cdata(policy_ref, TPM2B_NONCE, "policy_ref")

        timeout = ffi.new("TPM2B_TIMEOUT **")
        policyTicket = ffi.new("TPMT_TK_AUTH **")
        _chkrc(
            lib.Esys_PolicySecret(
                self.ctx,
                auth_handle,
                policy_session,
                session1,
                session2,
                session3,
                nonceTPM_cdata,
                cpHashA_cdata,
                policyRef_cdata,
                expiration,
                timeout,
                policyTicket,
            )
        )
        return (TPM2B_TIMEOUT(get_ptr(timeout)), TPMT_TK_AUTH(get_ptr(policyTicket)))

    def policy_ticket(
        self,
        policy_session,
        timeout,
        cp_hash_a,
        policy_ref,
        auth_name,
        ticket,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(policy_session, "policy_session")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        timeout_cdata = get_cdata(timeout, TPM2B_TIMEOUT, "timeout")
        cpHashA_cdata = get_cdata(cp_hash_a, TPM2B_DIGEST, "cp_hash_a")
        policyRef_cdata = get_cdata(policy_ref, TPM2B_NONCE, "policy_ref")
        authName_cdata = get_cdata(auth_name, TPM2B_NAME, "auth_name")
        ticket_cdata = get_cdata(ticket, TPMT_TK_AUTH, "ticket")

        _chkrc(
            lib.Esys_PolicyTicket(
                self.ctx,
                policy_session,
                session1,
                session2,
                session3,
                timeout_cdata,
                cpHashA_cdata,
                policyRef_cdata,
                authName_cdata,
                ticket_cdata,
            )
        )

    def policy_or(
        self,
        policy_session,
        p_hash_list,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(policy_session, "policy_session")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        pHashList_cdata = get_cdata(p_hash_list, TPML_DIGEST, "p_hash_list")

        _chkrc(
            lib.Esys_PolicyOR(
                self.ctx, policy_session, session1, session2, session3, pHashList_cdata
            )
        )

    def policy_pcr(
        self,
        policy_session,
        pcr_digest,
        pcrs,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(policy_session, "policy_session")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        pcrDigest_cdata = get_cdata(pcr_digest, TPM2B_DIGEST, "pcr_digest")
        pcrs_cdata = get_cdata(pcrs, TPML_PCR_SELECTION, "pcrs")

        _chkrc(
            lib.Esys_PolicyPCR(
                self.ctx,
                policy_session,
                session1,
                session2,
                session3,
                pcrDigest_cdata,
                pcrs_cdata,
            )
        )

    def PolicyLocality(
        self,
        policySession,
        locality,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(policySession, "policySession")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        if not isinstance(locality, int):
            raise TypeError(
                f"Expected locality to be of type TPMA_LOCALITY aka int, got {type(locality)}"
            )

        # Locality of 0-4 are indicated as bit index 0-4 being set. Localities 32-255 are
        # indicated as values. Thus locality of 0 is invalid, along with values greater than
        # 1 byte (255).
        if locality < 1 or locality > 255:
            raise ValueError(
                f"Expected locality to be in range of 1 - 255, got {locality}"
            )

        _chkrc(
            lib.Esys_PolicyLocality(
                self.ctx, policySession, session1, session2, session3, locality
            )
        )

    def PolicyNV(
        self,
        authHandle,
        nvIndex,
        policySession,
        operandB,
        operation,
        offset=0,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_friendly_int(authHandle, "authHandle", ESYS_TR)

        if not isinstance(nvIndex, int):
            raise TypeError(f"Expected nvIndex to be of type int, got {type(nvIndex)}")

        check_handle_type(policySession, "policySession")

        operandB_cdata = get_cdata(operandB, TPM2B_OPERAND, "operandB")

        check_friendly_int(operation, "operation", TPM2_EO)

        if not isinstance(offset, int):
            raise TypeError(f"Expected offset to be of type int, got {type(offset)}")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_PolicyNV(
                self.ctx,
                authHandle,
                nvIndex,
                policySession,
                session1,
                session2,
                session3,
                operandB_cdata,
                offset,
                operation,
            )
        )

    def PolicyCounterTimer(
        self,
        policySession,
        operandB,
        operation,
        offset=0,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(policySession, "policySession")

        operandB_cdata = get_cdata(operandB, TPM2B_OPERAND, "operandB")

        check_friendly_int(operation, "operation", TPM2_EO)

        if not isinstance(offset, int):
            raise TypeError(f"Expected offset to be of type int, got {type(offset)}")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_PolicyCounterTimer(
                self.ctx,
                policySession,
                session1,
                session2,
                session3,
                operandB_cdata,
                offset,
                operation,
            )
        )

    def PolicyCommandCode(
        self,
        policySession,
        code,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(policySession, "policySession")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")
        check_friendly_int(code, "code", TPM2_CC)

        _chkrc(
            lib.Esys_PolicyCommandCode(
                self.ctx, policySession, session1, session2, session3, code
            )
        )

    def PolicyPhysicalPresence(
        self,
        policySession,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(policySession, "policySession")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_PolicyPhysicalPresence(
                self.ctx, policySession, session1, session2, session3
            )
        )

    def PolicyCpHash(
        self,
        policySession,
        cpHashA,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(policySession, "policySession")

        cpHashA_cdata = get_cdata(cpHashA, TPM2B_DIGEST, "cpHashA")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_PolicyCpHash(
                self.ctx, policySession, session1, session2, session3, cpHashA_cdata
            )
        )

    def PolicyNameHash(
        self,
        policySession,
        nameHash,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(policySession, "policySession")

        nameHash_cdata = get_cdata(nameHash, TPM2B_DIGEST, "nameHash")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_PolicyNameHash(
                self.ctx, policySession, session1, session2, session3, nameHash_cdata
            )
        )

    def PolicyDuplicationSelect(
        self,
        policySession,
        objectName,
        newParentName,
        includeObject=False,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(policySession, "policySession")

        objectName_cdata = get_cdata(objectName, TPM2B_NAME, "objectName")
        newParentName_cdata = get_cdata(newParentName, TPM2B_NAME, "newParentName")

        if not isinstance(includeObject, bool):
            raise TypeError(
                f"Expected includeObject to be type bool, got {type(includeObject)}"
            )

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_PolicyDuplicationSelect(
                self.ctx,
                policySession,
                session1,
                session2,
                session3,
                objectName_cdata,
                newParentName_cdata,
                includeObject,
            )
        )

    def PolicyAuthorize(
        self,
        policySession,
        approvedPolicy,
        policyRef,
        keySign,
        checkTicket,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(policySession, "policySession")

        approvedPolicy_cdata = get_cdata(approvedPolicy, TPM2B_DIGEST, "approvedPolicy")
        policyRef_cdata = get_cdata(policyRef, TPM2B_NONCE, "policyRef")
        keySign_cdata = get_cdata(keySign, TPM2B_NAME, "keySign")
        checkTicket_cdata = get_cdata(checkTicket, TPMT_TK_VERIFIED, "checkTicket")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_PolicyAuthorize(
                self.ctx,
                policySession,
                session1,
                session2,
                session3,
                approvedPolicy_cdata,
                policyRef_cdata,
                keySign_cdata,
                checkTicket_cdata,
            )
        )

    def PolicyAuthValue(
        self,
        policySession,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(policySession, "policySession")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_PolicyAuthValue(
                self.ctx, policySession, session1, session2, session3
            )
        )

    def PolicyPassword(
        self,
        policySession,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(policySession, "policySession")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_PolicyPassword(
                self.ctx, policySession, session1, session2, session3
            )
        )

    def PolicyGetDigest(
        self,
        policySession,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(policySession, "policySession")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        policyDigest = ffi.new("TPM2B_DIGEST **")
        _chkrc(
            lib.Esys_PolicyGetDigest(
                self.ctx, policySession, session1, session2, session3, policyDigest
            )
        )
        return TPM2B_DIGEST(get_ptr(policyDigest))

    def PolicyNvWritten(
        self,
        policySession,
        writtenSet=True,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(policySession, "policySession")

        if not isinstance(writtenSet, bool):
            raise TypeError(
                f"Expected writtenSet to be type bool, got {type(writtenSet)}"
            )

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_PolicyNvWritten(
                self.ctx, policySession, session1, session2, session3, writtenSet
            )
        )

    def PolicyTemplate(
        self,
        policySession,
        templateHash,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(policySession, "policySession")

        templateHash_cdata = get_cdata(templateHash, TPM2B_DIGEST, "templateHash")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_PolicyTemplate(
                self.ctx,
                policySession,
                session1,
                session2,
                session3,
                templateHash_cdata,
            )
        )

    def PolicyAuthorizeNV(
        self,
        nvIndex,
        policySession,
        authHandle=0,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        if authHandle == 0:
            authHandle = nvIndex

        check_handle_type(authHandle, "authHandle")
        check_handle_type(nvIndex, "nvIndex")
        check_handle_type(policySession, "policySession")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_PolicyAuthorizeNV(
                self.ctx,
                authHandle,
                nvIndex,
                policySession,
                session1,
                session2,
                session3,
            )
        )

    def CreatePrimary(
        self,
        inSensitive,
        inPublic="rsa2048",
        primaryHandle=ESYS_TR.OWNER,
        outsideInfo=TPM2B_DATA(),
        creationPCR=TPML_PCR_SELECTION(),
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        inPublic_cdata = get_cdata(
            inPublic,
            TPM2B_PUBLIC,
            "inPublic",
            objectAttributes=TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATEPRIMARY_ATTRS,
        )
        inSensitive_cdata = get_cdata(
            inSensitive, TPM2B_SENSITIVE_CREATE, "inSensitive"
        )
        outsideInfo_cdata = get_cdata(outsideInfo, TPM2B_DATA, "outsideInfo")
        creationPCR_cdata = get_cdata(creationPCR, TPML_PCR_SELECTION, "creationPCR")

        objectHandle = ffi.new("ESYS_TR *")
        outPublic = ffi.new("TPM2B_PUBLIC **")
        creationData = ffi.new("TPM2B_CREATION_DATA **")
        creationHash = ffi.new("TPM2B_DIGEST **")
        creationTicket = ffi.new("TPMT_TK_CREATION **")
        _chkrc(
            lib.Esys_CreatePrimary(
                self.ctx,
                primaryHandle,
                session1,
                session2,
                session3,
                inSensitive_cdata,
                inPublic_cdata,
                outsideInfo_cdata,
                creationPCR_cdata,
                objectHandle,
                outPublic,
                creationData,
                creationHash,
                creationTicket,
            )
        )

        return (
            ESYS_TR(objectHandle[0]),
            TPM2B_PUBLIC(_cdata=get_ptr(outPublic)),
            TPM2B_CREATION_DATA(_cdata=get_ptr(creationData)),
            TPM2B_DIGEST(_cdata=get_ptr(creationHash)),
            TPMT_TK_CREATION(_cdata=get_ptr(creationTicket)),
        )

    def HierarchyControl(
        self,
        authHandle,
        enable,
        state,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):
        check_handle_type(
            authHandle,
            "authHandle",
            expected=(ESYS_TR.RH_ENDORSEMENT, ESYS_TR.RH_OWNER, ESYS_TR.RH_PLATFORM),
        )
        check_handle_type(
            enable,
            "enable",
            expected=(ESYS_TR.RH_ENDORSEMENT, ESYS_TR.RH_OWNER, ESYS_TR.RH_PLATFORM),
        )

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_HierarchyControl(
                self.ctx, authHandle, session1, session2, session3, enable, state
            )
        )

    def SetPrimaryPolicy(
        self,
        authHandle,
        authPolicy,
        hashAlg,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):
        check_handle_type(
            authHandle,
            "authHandle",
            expected=(ESYS_TR.RH_ENDORSEMENT, ESYS_TR.RH_OWNER, ESYS_TR.RH_PLATFORM),
        )

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        authPolicy_cdata = get_cdata(authPolicy, TPM2B_DIGEST, "authPolicy")
        check_friendly_int(hashAlg, "hashAlg", TPM2_ALG)

        _chkrc(
            lib.Esys_SetPrimaryPolicy(
                self.ctx,
                authHandle,
                session1,
                session2,
                session3,
                authPolicy_cdata,
                hashAlg,
            )
        )

    def ChangePPS(
        self,
        authHandle=ESYS_TR.RH_PLATFORM,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(authHandle, "authHandle", expected=(ESYS_TR.RH_PLATFORM,))

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(lib.Esys_ChangePPS(self.ctx, authHandle, session1, session2, session3))

    def ChangeEPS(
        self,
        authHandle=ESYS_TR.RH_PLATFORM,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(authHandle, "authHandle", expected=(ESYS_TR.RH_PLATFORM,))

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(lib.Esys_ChangeEPS(self.ctx, authHandle, session1, session2, session3))

    def Clear(
        self,
        authHandle,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(
            authHandle, "authHandle", expected=(ESYS_TR.RH_PLATFORM, ESYS_TR.RH_LOCKOUT)
        )

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(lib.Esys_Clear(self.ctx, authHandle, session1, session2, session3))

    def ClearControl(
        self,
        auth,
        disable,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(
            auth, "auth", expected=(ESYS_TR.RH_PLATFORM, ESYS_TR.RH_LOCKOUT)
        )

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_ClearControl(self.ctx, auth, session1, session2, session3, disable)
        )

    def HierarchyChangeAuth(
        self,
        authHandle,
        newAuth,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_HierarchyChangeAuth(
                self.ctx,
                authHandle,
                session1,
                session2,
                session3,
                TPM2B_pack(newAuth, t="TPM2B_AUTH"),
            )
        )

    def DictionaryAttackLockReset(
        self,
        lockHandle=ESYS_TR.RH_LOCKOUT,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(lockHandle, "lockHandle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")
        _chkrc(
            lib.Esys_DictionaryAttackLockReset(
                self.ctx, lockHandle, session1, session2, session3
            )
        )

    def DictionaryAttackParameters(
        self,
        newMaxTries,
        newRecoveryTime,
        lockoutRecovery,
        lockHandle=ESYS_TR.RH_LOCKOUT,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(lockHandle, "lockHandle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")
        _chkrc(
            lib.Esys_DictionaryAttackParameters(
                self.ctx,
                lockHandle,
                session1,
                session2,
                session3,
                newMaxTries,
                newRecoveryTime,
                lockoutRecovery,
            )
        )

    def PP_Commands(
        self,
        setList,
        clearList,
        auth=ESYS_TR.PLATFORM,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(auth, "auth")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")
        setList_cdata = get_cdata(setList, TPML_CC, "setList")
        clearList_cdata = get_cdata(clearList, TPML_CC, "clearList")
        _chkrc(
            lib.Esys_PP_Commands(
                self.ctx,
                auth,
                session1,
                session2,
                session3,
                setList_cdata,
                clearList_cdata,
            )
        )

    def SetAlgorithmSet(
        self,
        algorithmSet,
        authHandle=ESYS_TR.PLATFORM,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(authHandle, "authHandle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")
        _chkrc(
            lib.Esys_SetAlgorithmSet(
                self.ctx, authHandle, session1, session2, session3, algorithmSet
            )
        )

    def FieldUpgradeStart(
        self,
        authorization,
        keyHandle,
        fuDigest,
        manifestSignature,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(authorization, "authorization")
        check_handle_type(keyHandle, "keyHandle")
        fuDigest_cdata = get_cdata(fuDigest, TPM2B_DIGEST, "fuDigest")
        manifestSignature_cdata = get_cdata(
            manifestSignature, TPMT_SIGNATURE, "manifestSignature"
        )
        _chkrc(
            lib.Esys_FieldUpgradeStart(
                self.ctx,
                authorization,
                keyHandle,
                session1,
                session2,
                session3,
                fuDigest_cdata,
                manifestSignature_cdata,
            )
        )

    def FieldUpgradeData(
        self,
        fuData,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        fuData_cdata = get_cdata(fuData, TPM2B_MAX_BUFFER, "fuData")
        nextDigest = ffi.new("TPMT_HA **")
        firstDigest = ffi.new("TPMT_HA **")
        _chkrc(
            lib.Esys_FieldUpgradeData(
                self.ctx,
                session1,
                session2,
                session3,
                fuData_cdata,
                nextDigest,
                firstDigest,
            )
        )
        return (TPMT_HA(get_ptr(nextDigest)), TPMT_HA(get_ptr(firstDigest)))

    def FirmwareRead(
        self,
        sequenceNumber,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        fuData = ffi.new("TPM2B_MAX_BUFFER **")
        _chkrc(
            lib.Esys_FirmwareRead(
                self.ctx, session1, session2, session3, sequenceNumber, fuData
            )
        )
        return TPM2B_MAX_BUFFER(get_ptr(fuData))

    def ContextSave(self, saveHandle):
        check_handle_type(saveHandle, "saveHandle")
        context = ffi.new("TPMS_CONTEXT **")
        _chkrc(lib.Esys_ContextSave(self.ctx, saveHandle, context))
        return TPMS_CONTEXT(get_ptr(context))

    def ContextLoad(self, context):
        context_cdata = get_cdata(context, TPMS_CONTEXT, "context")
        loadedHandle = ffi.new("ESYS_TR *")
        _chkrc(lib.Esys_ContextLoad(self.ctx, context_cdata, loadedHandle))
        loadedHandleObject = loadedHandle[0]
        return loadedHandleObject

    def FlushContext(self, flushHandle):
        check_handle_type(flushHandle, "flushHandle")
        _chkrc(lib.Esys_FlushContext(self.ctx, flushHandle))

    def EvictControl(
        self,
        auth,
        objectHandle,
        persistentHandle,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(auth, "auth")
        check_handle_type(objectHandle, "objectHandle")
        check_handle_type(persistentHandle, "persistentHandle")
        newObjectHandle = ffi.new("ESYS_TR *")
        _chkrc(
            lib.Esys_EvictControl(
                self.ctx,
                auth,
                objectHandle,
                session1,
                session2,
                session3,
                persistentHandle,
                newObjectHandle,
            )
        )
        newObjectHandleObject = newObjectHandle[0]
        return newObjectHandleObject

    def ReadClock(
        self, session1=ESYS_TR.NONE, session2=ESYS_TR.NONE, session3=ESYS_TR.NONE
    ):

        currentTime = ffi.new("TPMS_TIME_INFO **")
        _chkrc(lib.Esys_ReadClock(self.ctx, session1, session2, session3, currentTime))
        return TPMS_TIME_INFO(get_ptr(currentTime))

    def ClockSet(
        self,
        auth,
        newTime,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(auth, "auth")
        _chkrc(lib.Esys_ClockSet(self.ctx, auth, session1, session2, session3, newTime))

    def ClockRateAdjust(
        self,
        auth,
        rateAdjust,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(auth, "auth")
        _chkrc(
            lib.Esys_ClockRateAdjust(
                self.ctx, auth, session1, session2, session3, rateAdjust
            )
        )

    def GetCapability(
        self,
        capability,
        prop,
        propertyCount=1,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_friendly_int(capability, "capability", TPM2_CAP)

        if not isinstance(prop, int):
            raise TypeError(f"Expected prop to be an int, got {type(prop)}")

        if not isinstance(propertyCount, int):
            raise TypeError(
                f"Expected propertyCount to be an int, got {type(propertyCount)}"
            )

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        moreData = ffi.new("TPMI_YES_NO *")
        capabilityData = ffi.new("TPMS_CAPABILITY_DATA **")
        _chkrc(
            lib.Esys_GetCapability(
                self.ctx,
                session1,
                session2,
                session3,
                capability,
                prop,
                propertyCount,
                moreData,
                capabilityData,
            )
        )
        return (bool(moreData[0]), TPMS_CAPABILITY_DATA(get_ptr(capabilityData)))

    def TestParms(
        self,
        parameters,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        parameters_cdata = get_cdata(parameters, TPMT_PUBLIC_PARMS, "parameters")
        _chkrc(
            lib.Esys_TestParms(self.ctx, session1, session2, session3, parameters_cdata)
        )

    def NV_DefineSpace(
        self,
        auth,
        publicInfo,
        authHandle=ESYS_TR.OWNER,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(authHandle, "authHandle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")
        auth_cdata = get_cdata(auth, TPM2B_AUTH, "auth", allow_none=True)
        publicInfo_cdata = get_cdata(publicInfo, TPM2B_NV_PUBLIC, "publicInfo")
        nvHandle = ffi.new("ESYS_TR *")
        _chkrc(
            lib.Esys_NV_DefineSpace(
                self.ctx,
                authHandle,
                session1,
                session2,
                session3,
                auth_cdata,
                publicInfo_cdata,
                nvHandle,
            )
        )
        nvHandleObject = nvHandle[0]
        return nvHandleObject

    def NV_UndefineSpace(
        self,
        nvIndex,
        authHandle=ESYS_TR.RH_OWNER,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(authHandle, "authHandle")
        check_handle_type(nvIndex, "nvIndex")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")
        _chkrc(
            lib.Esys_NV_UndefineSpace(
                self.ctx, authHandle, nvIndex, session1, session2, session3
            )
        )

    def NV_UndefineSpaceSpecial(
        self,
        nvIndex,
        platform=ESYS_TR.RH_PLATFORM,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(nvIndex, "nvIndex")
        check_handle_type(platform, "platform")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")
        _chkrc(
            lib.Esys_NV_UndefineSpaceSpecial(
                self.ctx, nvIndex, platform, session1, session2, session3
            )
        )

    def NV_ReadPublic(
        self,
        nvIndex,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(nvIndex, "nvIndex")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")
        nvPublic = ffi.new("TPM2B_NV_PUBLIC **")
        nvName = ffi.new("TPM2B_NAME **")
        _chkrc(
            lib.Esys_NV_ReadPublic(
                self.ctx, nvIndex, session1, session2, session3, nvPublic, nvName
            )
        )
        return (
            TPM2B_NV_PUBLIC(_cdata=get_ptr(nvPublic)),
            TPM2B_NAME(_cdata=get_ptr(nvName)),
        )

    def NV_Write(
        self,
        nvIndex,
        data,
        offset=0,
        authHandle=0,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        if authHandle == 0:
            authHandle = nvIndex
        check_handle_type(nvIndex, "nvIndex")
        check_handle_type(authHandle, "authHandle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")
        data_cdata = get_cdata(data, TPM2B_MAX_NV_BUFFER, "data")
        _chkrc(
            lib.Esys_NV_Write(
                self.ctx,
                authHandle,
                nvIndex,
                session1,
                session2,
                session3,
                data_cdata,
                offset,
            )
        )

    def NV_Increment(
        self,
        nvIndex,
        authHandle=0,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        if authHandle == 0:
            authHandle = nvIndex
        check_handle_type(authHandle, "authHandle")
        check_handle_type(nvIndex, "nvIndex")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")
        _chkrc(
            lib.Esys_NV_Increment(
                self.ctx, authHandle, nvIndex, session1, session2, session3
            )
        )

    def NV_Extend(
        self,
        nvIndex,
        data,
        authHandle=0,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        if authHandle == 0:
            authHandle = nvIndex
        check_handle_type(authHandle, "authHandle")
        check_handle_type(nvIndex, "nvIndex")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")
        data_cdata = get_cdata(data, TPM2B_MAX_NV_BUFFER, "data")
        _chkrc(
            lib.Esys_NV_Extend(
                self.ctx, authHandle, nvIndex, session1, session2, session3, data_cdata
            )
        )

    def NV_SetBits(
        self,
        nvIndex,
        bits,
        authHandle=0,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        if authHandle == 0:
            authHandle = nvIndex
        check_handle_type(authHandle, "authHandle")
        check_handle_type(nvIndex, "nvIndex")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")
        _chkrc(
            lib.Esys_NV_SetBits(
                self.ctx, authHandle, nvIndex, session1, session2, session3, bits
            )
        )

    def NV_WriteLock(
        self,
        nvIndex,
        authHandle=0,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        if authHandle == 0:
            authHandle = nvIndex
        check_handle_type(authHandle, "authHandle")
        check_handle_type(nvIndex, "nvIndex")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")
        _chkrc(
            lib.Esys_NV_WriteLock(
                self.ctx, authHandle, nvIndex, session1, session2, session3
            )
        )

    def NV_GlobalWriteLock(
        self,
        authHandle=ESYS_TR.RH_OWNER,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(authHandle, "authHandle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")
        _chkrc(
            lib.Esys_NV_GlobalWriteLock(
                self.ctx, authHandle, session1, session2, session3
            )
        )

    def NV_Read(
        self,
        nvIndex,
        size,
        offset=0,
        authHandle=0,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        if authHandle == 0:
            authHandle = nvIndex
        check_handle_type(nvIndex, "nvIndex")
        check_handle_type(authHandle, "authHandle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")
        data = ffi.new("TPM2B_MAX_NV_BUFFER **")
        _chkrc(
            lib.Esys_NV_Read(
                self.ctx,
                authHandle,
                nvIndex,
                session1,
                session2,
                session3,
                size,
                offset,
                data,
            )
        )
        return TPM2B_MAX_NV_BUFFER(get_ptr(data))

    def NV_ReadLock(
        self,
        nvIndex,
        authHandle=0,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        if authHandle == 0:
            authHandle = nvIndex
        check_handle_type(nvIndex, "nvIndex")
        check_handle_type(authHandle, "authHandle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")
        _chkrc(
            lib.Esys_NV_ReadLock(
                self.ctx, authHandle, nvIndex, session1, session2, session3
            )
        )

    def NV_ChangeAuth(
        self,
        nvIndex,
        newAuth,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(nvIndex, "nvIndex")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")
        newAuth_cdata = get_cdata(newAuth, TPM2B_DIGEST, "newAuth")
        _chkrc(
            lib.Esys_NV_ChangeAuth(
                self.ctx, nvIndex, session1, session2, session3, newAuth_cdata
            )
        )

    def NV_Certify(
        self,
        signHandle,
        nvIndex,
        qualifyingData,
        inScheme,
        size,
        offset=0,
        authHandle=0,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.PASSWORD,
        session3=ESYS_TR.NONE,
    ):

        if authHandle == 0:
            authHandle = nvIndex
        check_handle_type(signHandle, "signHandle")
        check_handle_type(authHandle, "authHandle")
        check_handle_type(nvIndex, "nvIndex")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")
        qualifyingData_cdata = get_cdata(qualifyingData, TPM2B_DATA, "qualifyingData")
        inScheme_cdata = get_cdata(inScheme, TPMT_SIG_SCHEME, "inScheme")

        if not isinstance(offset, int):
            raise TypeError(f"Expected offset to be of type int, got: {type(offset)}")

        certifyInfo = ffi.new("TPM2B_ATTEST **")
        signature = ffi.new("TPMT_SIGNATURE **")
        _chkrc(
            lib.Esys_NV_Certify(
                self.ctx,
                signHandle,
                authHandle,
                nvIndex,
                session1,
                session2,
                session3,
                qualifyingData_cdata,
                inScheme_cdata,
                size,
                offset,
                certifyInfo,
                signature,
            )
        )
        return (TPM2B_ATTEST(get_ptr(certifyInfo)), TPMT_SIGNATURE(get_ptr(signature)))

    def Vendor_TCG_Test(
        self,
        inputData,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):
        inputData_cdata = get_cdata(inputData, TPM2B_DATA, "inputData")
        outputData = ffi.new("TPM2B_DATA **")
        _chkrc(
            lib.Esys_Vendor_TCG_Test(
                self.ctx, session1, session2, session3, inputData_cdata, outputData
            )
        )
        return TPM2B_DATA(get_ptr(outputData))

    def load_blob(self, data: bytes, type: int = lib.FAPI_ESYSBLOB_CONTEXTLOAD) -> int:
        """load binary ESAPI object as binary blob. Supported are the types :const:`._libtpm2_pytss.lib.FAPI_ESYSBLOB_CONTEXTLOAD` and :const:`._libtpm2_pytss.lib.FAPI_ESYSBLOB_DESERIALIZE`.

        Args:
            data (bytes): Binary blob of the ESAPI object to load.
            type (int, optional): :const:`._libtpm2_pytss.lib.FAPI_ESYSBLOB_CONTEXTLOAD` or :const:`._libtpm2_pytss.lib.FAPI_ESYSBLOB_DESERIALIZE`. Defaults to :const:`._libtpm2_pytss.lib.FAPI_ESYSBLOB_CONTEXTLOAD`.

        Returns:
            int: The ESAPI handle to the loaded object.
        """
        esys_handle = ffi.new("ESYS_TR *")
        if type == lib.FAPI_ESYSBLOB_CONTEXTLOAD:
            offs = ffi.new("size_t *", 0)
            key_ctx = ffi.new("TPMS_CONTEXT *")
            _chkrc(lib.Tss2_MU_TPMS_CONTEXT_Unmarshal(data, len(data), offs, key_ctx))
            _chkrc(lib.Esys_ContextLoad(self.ctx, key_ctx, esys_handle))
        elif type == lib.FAPI_ESYSBLOB_DESERIALIZE:
            _chkrc(lib.Esys_TR_Deserialize(self.ctx, data, len(data), esys_handle))

        return esys_handle[0]
