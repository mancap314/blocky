# Purpose
Blocky is a method to ensure encrypted message exchange between two or
more participants ensuring the integrity of the communication

# Block Structure
We consider the situation where A wants to send a message M to B and C.
A produces a signature with his private key, ensuring he is the author of the message.
A also encrypts the message with his own public key, then with the public key of B, then
with the public key of C, such producing three encrypted messages MA, MB and MC.
Thos encrypted messages are packed in a dictionary recipient -> encrypted_message.
Each message also contains a timestamp, the creation time of the block in UTC format.
Last but not least, it contains the hash of the previous block.

The timestamp, the author, the encrypted message dictionary and the previous hash are
the hashed by the author of the message himself, with a nonce making the hash resecting
a given level of difficulty (number of 0 the hash has to begin with).

# Block verification
When a recipient gets a block, he decrypts its message with his private key, and
verfies the signature with the public key of the authori. The block timestamp is
 verified (it cannot be later than the current time). The block hash is also
 verified (consistence and difficulty)

# Conventions
Each participant is identified by the hash of his public key. Each block is identified
by its hash.

# Assurances
Once sent, a message cannot be modified since it would then not pass the hash check.
The author of the message is certified throuh his signature contained in the block.
The level of difficulty can be set according to a rule agreed by the participants in
order to prevent flooding. A block can have several forks, but the recipient of message
can be sure that he has got all the blocks up to the ones he received if he has the
previous block of every block.

