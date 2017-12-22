import os
from crypto import RSAEncryption

class User(object):
    def __init__(self, dir):
        self.encryptor = RSAEncryption(os.path.join(*[dir, 'keys', 'private-key.bin']), os.path.join(*[dir, 'keys', 'public-key.bin']))
        self.encryptor.generate_keys()

    def encrypt(self, message):
        return self.encryptor.encrypt(message)

    def _get_public_key(self):
        return self.encryptor._get_public_key()
