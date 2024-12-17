import datetime # to work with the timestamps
import hashlib # to generate hashes to keep record of the files
import json # to help in hash function

# The backbone of the project 
class Blockchain:
    def __init__(self):
        self.chain = []
        self.create_block(proof=1, previous_hash='0')
    
    # Creates blocks with the values and appneds each of them one after another as users upload data
    def create_block(self, proof, previous_hash):
        block = {'index': len(self.chain),
                 'timestamp': str(datetime.datetime.now()),
                 'proof': proof,
                 'previous_hash': previous_hash}
        self.chain.append(block)
        return block
    
    def print_previous_block(self):
        return self.chain[-1]

    # proof of work for the block, this could be made much more difficult, 
    # but in the beginning, i opined that such a function is not needed for
    #secure file storage system, but later realised that it could be a good
    # way to limit the rate of requests/uploads to not overburden the server.
    def proof_of_work(self, previous_proof):
        new_proof = 1
        check_proof = False
        while check_proof is False:
            hash_operation = hashlib.sha256(
                str(new_proof ** 2 - previous_proof ** 2).encode()).hexdigest()
            if hash_operation[:5] == '00000':
                check_proof = True
            else:
                new_proof += 1
        return new_proof

    # generates a hash for the upload, acts as an identifier for it
    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()
    
    # Checks whether the chain is valid or not by compairng the current hash and the previous hash
    def chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1
        while block_index < len(chain):
            block = chain[block_index]
            if block['previous_hash'] != self.hash(previous_block):
                return False
            previous_proof = previous_block['proof']
            proof = block['proof']
            hash_operation = hashlib.sha256(
                str(proof ** 2 - previous_proof ** 2).encode()).hexdigest()
            if hash_operation[:5] != '00000':
                return False
            previous_block = block
            block_index += 1
        return True


