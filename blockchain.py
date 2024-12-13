from cryptidy import asymmetric_encryption
import os
import datetime
import hashlib
import json
from flask import Flask, request, jsonify, render_template, send_file


class Blockchain:
    def __init__(self):
        self.chain = []
        self.create_block(proof=1, previous_hash='0')

    # def message(self):
    #     pub_key = open('user/pub/pub_key.key', "rb").read()
    #     uploaded_file = request.files['file']
    #     uploaded_file.save(uploaded_file.filename)
    #     if uploaded_file.filename != '':
    #         with open(uploaded_file.filename, 'r') as file:
    #             file_content = file.read()
    #         encrypted = asymmetric_encryption.encrypt_message(file_content, pub_key.decode())
    #         text_file = open(input('Name your file: '), "wb")
    #         text_file.write(encrypted)
    #         text_file.close()
    #         os.remove(str(uploaded_file.filename))
    #         return str(encrypted)

    def create_block(self, proof, previous_hash):
        block = {'index': len(self.chain) + 1,
                 'timestamp': str(datetime.datetime.now()),
                 'proof': proof,
                 'previous_hash': previous_hash}
        self.chain.append(block)
        return block

    def print_previous_block(self):
        return self.chain[-1]

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

    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

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


