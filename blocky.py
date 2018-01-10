import os
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import six
import datetime
from operator import itemgetter
from pytz import timezone
import json
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

def encrypt(message, recipient=None, auto=False):
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


def build_block(previous_block_hash, message, recipients, difficulty=0):
    blockstring = str(previous_block_hash)
    timestamp = datetime.datetime.utcfromtimestamp(datetime.datetime.now().timestamp()) #current utc time
    timestamp = timestamp.replace(tzinfo=timezone('UTC'))
    timestamp = timestamp.strftime('%Y-%m-%d %H:%M:%S %Z')
    blockstring += timestamp
    message_hash = SHA256.new(message.encode('utf8')).hexdigest()
    blockstring += str(message_hash)
    message_signature = sign(message_hash)
    blockstring += str(message_signature[0])
    blockstring += str(difficulty)

    with open(publicKeyPath) as f:
        key_text = f.read()
    author = SHA256.new(key_text.encode('utf8')).hexdigest()
    blockstring += str(author)

    message_encryptions = []
    auto_encryption = str(encrypt(message, auto=True))
    recipients.append(author)
    recipients.sort()
    for recipient in recipients:
        if recipient == author:
            message_encryptions.append({'recipient': recipient, 'encrypted': auto_encryption})
            blockstring += str(recipient) + auto_encryption
        else:
            encrypted_message = str(encrypt(message, recipient))
            recipient = str(recipient)
            message_encryptions.append({'recipient': recipient, 'encrypted': encrypted_message})
            blockstring += recipient + encrypted_message

    block_hash = str(SHA256.new(blockstring.strip().encode('utf8')).hexdigest())
    nonce = ''
    if difficulty > 0:
        nonce = -1
        while not block_hash.startswith('0' * difficulty):
            nonce += 1
            block_hash = str(SHA256.new((blockstring + str(nonce)).strip().encode('utf8')).hexdigest())


    print('blockstring: {}'.format(blockstring + str(nonce)))

    return {'previous_block_hash': previous_block_hash, 'timestamp': timestamp, 'author': author,
            'message_hash': message_hash, 'encryptions': message_encryptions,  'difficulty': str(difficulty),
            'nonce': nonce, 'block_hash': block_hash, 'signature': message_signature}


def verify_block_content(block):
    # verify signature
    signature_ok = verify_signature(block['message_hash'], block['signature'], block['author'])
    if not signature_ok:
        print('WARNING: block signature not correct')

    # verify difficulty
    difficulty_ok = True
    difficulty = int(block['difficulty'])
    if difficulty > 0:
        difficulty_ok = block['block_hash'].startswith('0' * difficulty)
    if not difficulty_ok:
        print('WARNING: block hash does not respect block difficulty')

    # verify block hash
    blockstring = str(block['previous_block_hash']) + str(block['timestamp']) + str(block['message_hash']) + str(block['signature'][0]) + str(block['difficulty']) + str(block['author'])
    encryptions = block['encryptions']
    encryptions = sorted(encryptions, key=itemgetter('recipient'))
    for encryption in encryptions:
        blockstring += str(encryption['recipient']) + str(encryption['encrypted'])
    blockstring += str(block['nonce'])
    print('blockstring: {}'.format(blockstring))
    block_hash = str(SHA256.new(str(blockstring).strip().encode('utf8')).hexdigest())
    print('block_hash computed: {}\nblock_hash gotten: {}'.format(block_hash, block['block_hash']))
    block_hash_ok = (block_hash == block['block_hash'])
    if not block_hash_ok:
        print('WARNING: block_hash is not valid for this block')

    #verify that the timestamp doesn't lie in the future
    tblock_timestamp = datetime.datetime.strptime(block['timestamp'], '%Y-%m-%d %H:%M:%S %Z')
    now = datetime.datetime.utcfromtimestamp(datetime.datetime.now().timestamp())
    timestamp_ok = (tblock_timestamp < now)
    if not timestamp_ok:
        print('WARNING: Block timestamp lies in the future')

    return signature_ok & difficulty_ok & block_hash_ok & timestamp_ok


def write_block(block):
    name = block['block_hash']
    filename = os.path.join(chain_directory, '{}.json'.format(name))
    with open(filename, 'w') as f:
        json.dump(block, f)

def read_block(name):
    filename = os.path.join(chain_directory, '{}.json'.format(name))
    block = json.load(open(filename))
    return block








