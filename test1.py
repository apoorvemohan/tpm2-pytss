from tpm2_pytss import *
from base64 import b16encode

ectx = ESAPI()

tcti = TctiLdr('device', '/dev/tpmrm0')
ectx = ESAPI(tcti)

inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("password"))
        )
parentHandle, _, _, _, _ = ectx.create_ek(
            inSensitive, "rsa2048:aes128cfb", ESYS_TR.RH_ENDORSEMENT
        )
primaryKeyName = ectx.read_public(parentHandle)[1]
print("Created Key:")
print(ectx.read_public(parentHandle)[0].toPEM())
ectx.shutdown(TPM2_SU.CLEAR)

alg = "rsa2048"
attrs = (
            TPMA_OBJECT.RESTRICTED
            | TPMA_OBJECT.DECRYPT
            | TPMA_OBJECT.USERWITHAUTH
            | TPMA_OBJECT.SENSITIVEDATAORIGIN
        )
childInPublic = TPM2B_PUBLIC(TPMT_PUBLIC.parse(alg=alg, objectAttributes=attrs))
childInSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("childpassword"))
        )
priv, pub, _, _, _ = ectx.create(
            parentHandle, childInSensitive, childInPublic
        )
childHandle = ectx.load(parentHandle, priv, pub)
credential = TPM2B_DIGEST("this is my credential")
credentialBlob, secret = ectx.make_credential(
            childHandle, credential, primaryKeyName
        )
ectx.set_auth(childHandle, "childpassword")
certInfo = ectx.activate_credential(
            parentHandle, childHandle, credentialBlob, secret
        )
