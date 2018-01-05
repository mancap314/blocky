import os
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import six
import base64

home_directory = os.path.expanduser('~')
base_directory = os.path.join(home_directory, '.blocky')
chain_directory = os.path.join(base_directory, 'chains')
foreignPublicKeysDirectory = os.path.join(base_directory, 'fpkeys')
selfkeysDirectory = os.path.join(base_directory, 'skeys')
privatKeyPath = os.path.join(selfkeysDirectory, 'private.key')
publicKeyPath = os.path.join(selfkeysDirectory, 'public.key')

def setup():
    dirs = [base_directory, chain_directory, foreignPublicKeysDirectory, selfkeysDirectory]
    for dir in dirs:
        print('dir: {}'.format(dir))
        if not os.path.isdir(dir):
            os.makedirs(dir)

def create_self_keys():
    """Be careful rewrite your keys"""
    random_generator = Random.new().read
    key = RSA.generate(1024, random_generator)
    private, public = key.exportKey(), key.publickey().exportKey()

    with open(privatKeyPath, 'wb') as private_file:
        private_file.write(private)
    with open(publicKeyPath, 'wb') as public_file:
        public_file.write(public)


def to_format_for_encrypt(value):
    if isinstance(value, int):
        return six.binary_type(value)
    for str_type in six.string_types:
        if isinstance(value, str_type):
            return value.encode('utf8')
    if isinstance(value, six.binary_type):
        return value

def encrypt(message, recipient):
    publicKeyPathRecipient = os.path.join(foreignPublicKeysDirectory, '{}.key'.format(recipient))
    with open(publicKeyPathRecipient) as f:
        key_text = f.read()
    public_key_object = RSA.importKey(key_text)
    cipher = PKCS1_OAEP.new(public_key_object)
    message = to_format_for_encrypt(message)
    encrypted_message = cipher.encrypt(message)
    return encrypted_message


def decrypt(message):
    # read key file
    with open(privatKeyPath) as f:
        key_text = f.read()
    private_key_object = RSA.importKey(key_text)
    cipher = PKCS1_OAEP.new(private_key_object)
    decrypted_message = cipher.decrypt(message)
    return six.text_type(decrypted_message, encoding='utf8')

def sign(text):
    with open(privatKeyPath) as f:
        key_text = f.read()
    private_key_object = RSA.importKey(key_text)
    text = text.encode('utf8')
    hash = SHA256.new(text).digest()
    signature = private_key_object.sign(hash, '')
    return signature

def verify_signature(text, signature, author):
    text = text.encode('utf8')
    authorPublicKeyPath = os.path.join(foreignPublicKeysDirectory, '{}.key'.format(author))
    with open(authorPublicKeyPath) as f:
        key_text = f.read()
    authorPublicKey = RSA.importKey(key_text)
    hash = SHA256.new(text).digest()
    return authorPublicKey.verify(hash, signature)


# TEST
# setup() #OK
# create_self_keys() #OK
# print(sign('truc'))