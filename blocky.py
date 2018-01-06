import os
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import six
import datetime
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

def encrypt(message, recipient, auto=False):
    if auto:
        with open(publicKeyPath) as f:
            key_text = f.read()
    else:
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
    hash = SHA256.new(text).hexdigest()
    signature = private_key_object.sign(hash, '')
    return signature

def verify_signature(text, signature, author):
    text = text.encode('utf8')
    authorPublicKeyPath = os.path.join(foreignPublicKeysDirectory, '{}.key'.format(author))
    with open(authorPublicKeyPath) as f:
        key_text = f.read()
    authorPublicKey = RSA.importKey(key_text)
    hash = SHA256.new(text).hexdigest()
    return authorPublicKey.verify(hash, signature)


def build_block(previous_block_hash, message, recipients, difficulty=0):
    blockstring = previous_block_hash
    timestamp = datetime.datetime.utcfromtimestamp(datetime.datetime.now().timestamp()) #current utc time
    timestamp = timestamp.strftime('%Y-%m-%d %H:%M:%S')
    blockstring += timestamp
    message_hash = SHA256.new(message).hexdigest()
    blockstring += message_hash
    message_signature = sign(message_hash)
    blockstring += message_signature

    with open(publicKeyPath) as f:
        key_text = f.read()
    author = SHA256.new(key_text).hexdigest()
    blockstring += str(author)

    message_encryptions = []
    auto_encryption = str(encrypt(message, auto=True))
    blockstring += auto_encryption
    message_encryptions.append({'recipent': 'auto', 'encrypted': auto_encryption})
    recipients = recipients.sort()
    for recipient in recipients:
        encrypted_message = str(encrypt(message, recipient))
        recipient = str(recipient)
        message_encryptions.append({'recipient': recipient, 'encrypted': encrypted_message})
        blockstring += recipient + encrypted_message

    block_hash = str(SHA256.new(key_text).hexdigest())
    if difficulty > 0:
        nonce = 0
        while not block_hash.startswith('0' * difficulty):
            block_hash = str(SHA256.new(blockstring).hexdigest() + str(nonce))
            nonce += 1

    return {'previous_block_has': previous_block_hash, 'timestamp': timestamp, 'author': author,
            'message_hash': message_hash, 'encryptions': message_encryptions,  'difficulty': str(difficulty),
            'nonce': nonce, 'block_hash': block_hash}




