import hashlib as hasher
import datetime as dt

class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = ''
        # self.hash = self.hash_block()

    def hash_block(self):
        sha = hasher.sha256()
        sha.update((str(self.index) + str(self.timestamp) + str(self.data) + str(self.previous_hash)).encode('utf8'))
        return sha.hexdigest()

    def authentify(self, nounce, hash):
        sha = hasher.sha256()
        sha.update(
            (str(self.index) + str(self.timestamp) + str(self.data) + str(self.previous_hash) + str(nounce)).encode(
                'utf8'))
        hsh = str(sha.hexdigest())
        if hsh == hash:
            self.nounce = nounce
            self.hash = hash
            return True
        else:
            print('Error: This block cannot be authentified with the provided nounce and hash')
            return False



def create_genesis_block():
    return Block(0, dt.datetime.now(), 'Genesis Block', '0')


def next_block(last_block):
    this_index = last_block.index + 1
    this_timestamp = dt.datetime.now()
    this_data = "Hey, I am block {}".format(this_index)
    this_previous_hash = last_block.hash
    return Block(this_index, this_timestamp, this_data, this_previous_hash)


def mine_block(block):
    hash_ = ''
    i = 0
    while not hash_.startswith('0'):
        i += 1
        sha = hasher.sha256()
        sha.update((str(block.index) + str(block.timestamp) + str(block.data) + str(block.previous_hash) + str(i)).encode('utf8'))
        hash_ = str(sha.hexdigest())

    print('found nounce: {}\nhash: {}'.format(i, hash_))
    return i, hash_


# Create blockchain:
bchain = [create_genesis_block()]

n_block_toadd = 20
for i in range(n_block_toadd):
    block = next_block(bchain[i])
    nounce, hsh_ = mine_block(block)
    if block.authentify(nounce, hsh_):
        bchain.append(block)
        print('Block added:\nindex: {}\ntimestamp: {}\ndata: {}\nprevious hash: {}\nhash: {}\nnounce: {}\n'.format(bchain[i+1].index, bchain[i+1].timestamp, bchain[i+1].data, bchain[i+1].previous_hash, bchain[i+1].hash, bchain[i+1].nounce))


