import six
from Crypto import Random
from Crypto.PublicKey import RSA
import base64
import os


class RSAEncryption(object):
    def __init__(self, private_key_path, public_key_path):
        self.private_key_path = private_key_path #'/home/manuel/keys/private-key.bin'
        self.public_key_path = public_key_path #'/home/manuel/keys/public-key.bin'

    def encrypt(self, message):
        public_key = self._get_public_key()
        public_key_object = RSA.importKey(public_key)
        random_phrase = 'M'
        encrypted_message = public_key_object.encrypt(self._to_format_for_encrypt( message), random_phrase)[0]
        # use base64 for save encrypted_message in database without problems with encoding
        return base64.b64encode(encrypted_message)

    def decrypt(self, encoded_encrypted_message):
        encrypted_message = base64.b64decode(encoded_encrypted_message)
        private_key = self._get_private_key()
        private_key_object = RSA.importKey(private_key)
        decrypted_message = private_key_object.decrypt(encrypted_message)
        return six.text_type(decrypted_message, encoding='utf8')

    def generate_keys(self):
        """Be careful rewrite your keys"""
        random_generator = Random.new().read
        key = RSA.generate(1024, random_generator)
        private, public = key.exportKey(), key.publickey().exportKey()

        if os.path.isfile(self.public_key_path):
            print('WARNING: No key generated since already exists')
        self.create_directories()

        with open(self.private_key_path, 'wb') as private_file:
            private_file.write(private)
        with open(self.public_key_path, 'wb') as public_file:
            public_file.write(public)


    def create_directories(self, for_private_key=True):
        public_key_path = os.path.dirname(self.public_key_path)
        if not os.path.exists(public_key_path):
            os.makedirs(public_key_path)
        if for_private_key:
            private_key_path = os.path.dirname(self.private_key_path)
            if not os.path.exists(private_key_path):
                os.makedirs(private_key_path)

    def _get_public_key(self):
        """run generate_keys() before get keys """
        with open(self.public_key_path, 'r') as _file:
            return _file.read()

    def _get_private_key(self):
        """run generate_keys() before get keys """
        with open(self.private_key_path, 'r') as _file:
            return _file.read()

    def _to_format_for_encrypt(self, value):
        if isinstance(value, int):
            return six.binary_type(value)
        for str_type in six.string_types:
            if isinstance(value, str_type):
                return value.encode('utf8')
        if isinstance(value, six.binary_type):
            return value


encryptor = RSAEncryption()
encryptor.generate_keys()
print(encryptor._get_public_key())
print(encryptor._get_private_key())

message = 'waouh trop la classe ce message'
encrypted_message = encryptor.encrypt(message)
print('encrypted message:\n{}'.format(encrypted_message))
decrypted_message = encryptor.decrypt(encrypted_message)
print('decrypted message:\n{}'.format(decrypted_message))