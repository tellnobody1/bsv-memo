from bitsv import Key
from bitsv.network import get_fee
from bitsv.network.meta import Unspent
from bitsv.transaction import create_p2pkh_transaction
from bitsv.transaction import calc_txid
from bitsv.transaction import sanitize_tx_data
import json
import requests

def get_unspents(address):
  r = requests.get("https://bchsvexplorer.com/api/addr/{}/utxo".format(address), timeout=30)
  r.raise_for_status()
  print(r.text)
  utxos = [
    Unspent(amount=utxo['satoshis'],
            confirmations=utxo['confirmations'],
            txid=utxo['txid'],
            txindex=utxo['vout'])
    for utxo in r.json()
  ]
  return sorted(utxos, key=lambda utxo: (-utxo.confirmations, utxo.amount))

def create_transaction(key, msg):
  unspents, outputs = sanitize_tx_data(
      get_unspents(key.address),
      [],
      get_fee('slow'),
      key.address,
      combine=True,
      message=msg,
      compressed=key.is_compressed(),
      custom_pushdata=False
  )
  return create_p2pkh_transaction(key, unspents, outputs, custom_pushdata=False)

def send(tx_hex):
  r = requests.post(
    'https://api.whatsonchain.com/v1/bsv/main/tx/raw',
    data=json.dumps({'txhex': tx_hex}),
    headers={
      'Content-Type': 'application/json'
    },
  )
  print(r.text)
  r.raise_for_status()
  print(r.json()['txid'])
  return calc_txid(tx_hex)

msg = 'x'
key = Key('')
tx_hex = create_transaction(key, msg)
txid = send(tx_hex)
print(txid)

# import bitsv
# from bitsv.format import (
#     bytes_to_wif, public_key_to_address, public_key_to_coords, wif_to_bytes,
#     address_to_public_key_hash
# )
# from bitsv.crypto import ECPrivateKey
# from bitsv.network import NetworkAPI, get_fee, satoshi_to_currency_cached, fees
# from bitsv.transaction import (
#     calc_txid, sanitize_tx_data,
#     OP_CHECKSIG, OP_DUP, OP_EQUALVERIFY, OP_HASH160, OP_PUSH_20
#     )
# from bitsv.utils import (
#     bytes_to_hex, chunk_data, hex_to_bytes, int_to_varint
# )
# from bitsv.crypto import double_sha256, sha256
# import requests
# import json
# from decimal import Decimal

# from bitsv.network import currency_to_satoshi
# from bitsv.network.meta import Unspent

# # left here as a reminder to normalize get_transaction()
# from bitsv.network.transaction import Transaction, TxInput, TxOutput
# from bitsv.constants import BSV

# msg = 'xyu'
# wif = ''

# private_key_bytes, compressed, prefix = wif_to_bytes(wif)
# print("compressed={}".format(compressed))
# _pk = ECPrivateKey(private_key_bytes)
# _public_key = _pk.public_key.format(compressed=compressed)
# print("len(_public_key)={}".format(len(_public_key)))
# network_api = NetworkAPI(prefix)
# _address = public_key_to_address(_public_key, prefix=prefix)
# unspents = network_api.get_unspents(_address)
# print("unspents={}".format(unspents))
# balance = sum(unspent.amount for unspent in unspents)
# print("balance={}".format(balance))

# unspents, outputs = sanitize_tx_data(
#   unspents,
#   outputs=[],
#   fee=get_fee('slow'),
#   leftover=_address,
#   combine=True,
#   message=msg,
#   compressed=True if len(_public_key) == 33 else False,
#   custom_pushdata=False
# )
# print(unspents)
# print(outputs)

# _scriptcode = (OP_DUP + OP_HASH160 + OP_PUSH_20 + address_to_public_key_hash(_address) + OP_EQUALVERIFY + OP_CHECKSIG)

# public_key_len = len(_public_key).to_bytes(1, byteorder='little')

# scriptCode_len = int_to_varint(len(_scriptcode))

# version = 0x01.to_bytes(4, byteorder='little')
# lock_time = 0x00.to_bytes(4, byteorder='little')
# hash_type = 0x01.to_bytes(4, byteorder='little')
# input_count = int_to_varint(len(unspents))
# output_count = int_to_varint(len(outputs))


# def get_op_pushdata_code(dest):
#     length_data = len(dest)
#     if length_data <= 0x4c:  # (https://en.bitcoin.it/wiki/Script)
#         return length_data.to_bytes(1, byteorder='little')
#     elif length_data <= 0xff:
#         return b'\x4c' + length_data.to_bytes(1, byteorder='little')  # OP_PUSHDATA1 format
#     elif length_data <= 0xffff:
#         return b'\x4d' + length_data.to_bytes(2, byteorder='little')  # OP_PUSHDATA2 format
#     else:
#         return b'\x4e' + length_data.to_bytes(4, byteorder='little')  # OP_PUSHDATA4 format

# def construct_output_block(outputs, custom_pushdata=False):

#     output_block = b''

#     for data in outputs:
#         dest, amount = data

#         # Real recipient
#         if amount:
#             script = (OP_DUP + OP_HASH160 + OP_PUSH_20 +
#                       address_to_public_key_hash(dest) +
#                       OP_EQUALVERIFY + OP_CHECKSIG)

#             output_block += amount.to_bytes(8, byteorder='little')

#         # Blockchain storage
#         else:
#             script = b'\00' + b'\x6a' + get_op_pushdata_code(dest) + dest

#             output_block += b'\x00\x00\x00\x00\x00\x00\x00\x00'

#         # Script length in wiki is "Var_int" but there's a note of "modern BitcoinQT" using a more compact "CVarInt"
#         output_block += int_to_varint(len(script))
#         output_block += script

#     return output_block

# output_block = construct_output_block(outputs, custom_pushdata=False)


# class TxIn:
#     __slots__ = ('script', 'script_len', 'txid', 'txindex', 'amount')

#     def __init__(self, script, script_len, txid, txindex, amount):
#         self.script = script
#         self.script_len = script_len
#         self.txid = txid
#         self.txindex = txindex
#         self.amount = amount

#     def __eq__(self, other):
#         return (self.script == other.script and
#                 self.script_len == other.script_len and
#                 self.txid == other.txid and
#                 self.txindex == other.txindex and
#                 self.amount == other.amount)

#     def __repr__(self):
#         return 'TxIn({}, {}, {}, {}, {})'.format(
#             repr(self.script),
#             repr(self.script_len),
#             repr(self.txid),
#             repr(self.txindex),
#             repr(self.amount)
#         )

# # Optimize for speed, not memory, by pre-computing values.
# inputs = []
# for unspent in unspents:
#     txid = hex_to_bytes(unspent.txid)[::-1]
#     txindex = unspent.txindex.to_bytes(4, byteorder='little')
#     amount = unspent.amount.to_bytes(8, byteorder='little')

#     inputs.append(TxIn('', 0, txid, txindex, amount))

# hashPrevouts = double_sha256(b''.join([i.txid+i.txindex for i in inputs]))
# hashSequence = double_sha256(b''.join([0xffffffff.to_bytes(4, byteorder='little') for i in inputs]))
# hashOutputs = double_sha256(output_block)

# # scriptCode_len is part of the script.
# for i, txin in enumerate(inputs):
#     to_be_hashed = (
#         version +
#         hashPrevouts +
#         hashSequence +
#         txin.txid +
#         txin.txindex +
#         scriptCode_len +
#         _scriptcode +
#         txin.amount +
#         0xffffffff.to_bytes(4, byteorder='little') +
#         hashOutputs +
#         lock_time +
#         hash_type
#     )
#     hashed = sha256(to_be_hashed)  # BIP-143: Used for Bitcoin SV

#     # signature = private_key.sign(hashed) + b'\x01'
#     signature = _pk.sign(hashed) + b'\x41'

#     script_sig = (
#         len(signature).to_bytes(1, byteorder='little') +
#         signature +
#         public_key_len +
#         _public_key
#     )

#     inputs[i].script = script_sig
#     inputs[i].script_len = int_to_varint(len(script_sig))


# def construct_input_block(inputs):

#     input_block = b''
#     sequence = 0xffffffff.to_bytes(4, byteorder='little')

#     for txin in inputs:
#         input_block += (
#             txin.txid +
#             txin.txindex +
#             txin.script_len +
#             txin.script +
#             sequence
#         )

#     return input_block

# tx_hex = bytes_to_hex(
#     version +
#     input_count +
#     construct_input_block(inputs) +
#     output_count +
#     output_block +
#     lock_time
# )

# print(json.dumps({'rawtx': tx_hex}))

# r = requests.post(
#     'https://api.whatsonchain.com/v1/bsv/main/tx/raw',
#     data=json.dumps({'txhex': tx_hex}),
#     headers={
#         'Content-Type': 'application/json'
#     },
# )
# print(r.text)
# r.raise_for_status()
# print(r.json()['txid'])

# txid = calc_txid(tx_hex)
# print("txid={}".format(txid))
