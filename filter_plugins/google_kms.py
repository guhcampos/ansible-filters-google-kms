# Make coding more python3-ish
from __future__ import absolute_import, division, print_function
import os
__metaclass__ = type

import base64
from google.cloud import kms_v1

KMS_PROJECT = os.environ.get("KMS_PROJECT", None)
KMS_LOCATION = os.environ.get("KMS_LOCATION", None)
KMS_KEYRING = os.environ.get("KMS_KEYRING", None)
KMS_KEYNAME = os.environ.get("KMS_KEYNAME", None)


def google_kms_decrypt(a, *args, **kwargs):

    kms_project = kwargs.get("kms_project", KMS_PROJECT)
    kms_location = kwargs.get("kms_location", KMS_LOCATION)
    kms_keyring = kwargs.get("kms_keyring", KMS_KEYRING)
    kms_keyname = kwargs.get("kms_key", KMS_KEYNAME)

    if kms_project is None:
        raise ValueError("Missing value for KMS Project")

    if kms_location is None:
        raise ValueError("Missing value for KMS Location")

    if kms_keyring is None:
        raise ValueError("Missing value for KMS keyring")

    if kms_keyname is None:
        raise ValueError("Missing value for KMS keyname")

    kms = kms_v1.KeyManagementServiceClient()
    keyname = kms.crypto_key_path_path(kms_project, kms_location, kms_keyring,
                                       kms_keyname)

    return str(
        kms.decrypt(keyname,
                    base64.b64decode(a)).plaintext.decode("ascii").strip())


class FilterModule(object):

    def filters(self):
        return {"google_kms_decrypt": google_kms_decrypt}
