# Make coding more python3-ish
from __future__ import absolute_import, division, print_function

__metaclass__ = type

import base64
from google.cloud import kms_v1


def google_kms_decrypt(a, *args, **kwargs):

    kms = kms_v1.KeyManagementServiceClient()
    keyname = kms.crypto_key_path_path(
        kwargs["kms_project"],
        kwargs["kms_location"],
        kwargs["kms_keyring"],
        kwargs["kms_key"],
    )

    return str(
        kms.decrypt(keyname, base64.b64decode(a)).plaintext.decode("ascii").strip()
    )


class FilterModule(object):
    def filters(self):
        return {"google_kms_decrypt": google_kms_decrypt}

