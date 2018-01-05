import blocky as b

import os
import six
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP

home_directory = os.path.expanduser('~')
base_directory = os.path.join(home_directory, '.blocky')
foreignPublicKeysDirectory = os.path.join(base_directory, 'fpkeys')
selfkeysDirectory = os.path.join(base_directory, 'skeys')
privatKeyPath = os.path.join(selfkeysDirectory, 'private.key')
publicKeyPath = os.path.join(selfkeysDirectory, 'public.key')
privateKeysDirectory_fake = os.path.join(base_directory, 'private_keys_fake')

def generate_foreign_keys(n=10):
    if not os.path.isdir(privateKeysDirectory_fake):
        os.makedirs(privateKeysDirectory_fake)
    for _ in range(n):
        random_generator = Random.new().read
        key = RSA.generate(1024, random_generator)
        private, public = key.exportKey(), key.publickey().exportKey()
        hash = SHA256.new(public).hexdigest()
        keyname = '{}.key'.format(hash)
        publickeypath = os.path.join(foreignPublicKeysDirectory, keyname)
        privatekeypath = os.path.join(privateKeysDirectory_fake, keyname)
        with open(publickeypath, 'wb') as public_file:
            public_file.write(public)
        with open(privatekeypath, 'wb') as private_file:
            private_file.write(private)


def sign(text, privateKeyPath):
    with open(privateKeyPath) as f:
        key_text = f.read()
    private_key_object = RSA.importKey(key_text)
    text = text.encode('utf8')
    hash = SHA256.new(text).digest()
    signature = private_key_object.sign(hash, '')
    return signature


def test_sign(text='trucbidulemachin'):
    foreignPrivateKeyFiles = [f for f in os.listdir(privateKeysDirectory_fake) if os.path.isfile(os.path.join(privateKeysDirectory_fake, f))]
    text = text.encode('utf8')
    hashtext = SHA256.new(text).hexdigest()
    for pkey in foreignPrivateKeyFiles:
        signature = sign(hashtext, os.path.join(privateKeysDirectory_fake, pkey))
        author = pkey.split('.')[0]
        print(b.verify_signature(hashtext, signature, author))

def self_encrypt(message):
    with open(publicKeyPath) as f:
        key_text = f.read()
    public_key_object = RSA.importKey(key_text)
    cipher = PKCS1_OAEP.new(public_key_object)
    message = b.to_format_for_encrypt(message)
    encrypted_message = cipher.encrypt(message)
    return encrypted_message

def test_decrypt(message='trucbidulemachinchouette'):
    encrypted_message = self_encrypt(message)
    decrypted_message = b.decrypt(encrypted_message)
    print('message: {}, decrypted message: {}, {}'.format(message, decrypted_message, message == decrypted_message))

def decrypt(message, pkeyfile):
    pkeypath = os.path.join(privateKeysDirectory_fake, pkeyfile)
    with open(pkeypath) as f:
        key_text = f.read()
    private_key_object = RSA.importKey(key_text)
    cipher = PKCS1_OAEP.new(private_key_object)
    decrypted_message = cipher.decrypt(message)
    return six.text_type(decrypted_message, encoding='utf8')

def test_encrypt(message='voilivoilou'):
    foreignPublicKeyFiles = [f for f in os.listdir(foreignPublicKeysDirectory) if
                              os.path.isfile(os.path.join(privateKeysDirectory_fake, f))]
    for pkey in foreignPublicKeyFiles:
        recipient = pkey.split('.')[0]
        encrypted_message = b.encrypt(message, recipient)
        decrypted_message = decrypt(encrypted_message, pkey)
        print('message: {}, decrypted message: {}, {}'.format(message, decrypted_message, message == decrypted_message))


# generate_foreign_keys() #OK
# test_sign() #OK
# test_decrypt() #OK
# test_encrypt() #OK