from bitsv import Key
from bitsv.transaction import TxIn
from collections import deque
from api import get_unspents, send
import math
from hashlib import sha256 as _sha256
from binascii import hexlify
from bitsv.network.meta import Unspent

def sha256(bytestr):
  return _sha256(bytestr).digest()

def double_sha256(bytestr):
  return _sha256(_sha256(bytestr).digest()).digest()

def double_sha256_checksum(bytestr):
  return double_sha256(bytestr)[:4]

def int_to_unknown_bytes(num, byteorder='big'):
  """Converts an int to the least number of bytes as possible."""
  return num.to_bytes((num.bit_length() + 7) // 8 or 1, byteorder)

def b58decode(string):
  BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
  BASE58_ALPHABET_INDEX = {char: index for index, char in enumerate(BASE58_ALPHABET)}

  alphabet_index = BASE58_ALPHABET_INDEX

  num = 0

  try:
      for char in string:
          num *= 58
          num += alphabet_index[char]
  except KeyError:
      raise ValueError('"{}" is an invalid base58 encoded '
                        'character.'.format(char)) from None

  bytestr = int_to_unknown_bytes(num)

  pad = 0
  for char in string:
      if char == '1':
          pad += 1
      else:
          break

  return b'\x00' * pad + bytestr

def b58decode_check(string):
  decoded = b58decode(string)
  shortened = decoded[:-4]
  decoded_checksum = decoded[-4:]
  hash_checksum = double_sha256_checksum(shortened)
  if decoded_checksum != hash_checksum:
    raise ValueError('Decoded checksum {} derived from "{}" is not equal to hash checksum {}.'.format(decoded_checksum, string, hash_checksum))
  return shortened

def address_to_public_key_hash(address):
  return b58decode_check(address)[1:]

def get_op_pushdata_code(dest):
  OP_PUSHDATA1 = b'\x4c'
  OP_PUSHDATA2 = b'\x4d'
  OP_PUSHDATA4 = b'\x4e'
  length_data = len(dest)
  if length_data <= 0x4c:  # (https://en.bitcoin.it/wiki/Script)
    return length_data.to_bytes(1, byteorder='little')
  elif length_data <= 0xff:
    return OP_PUSHDATA1 + length_data.to_bytes(1, byteorder='little')  # OP_PUSHDATA1 format
  elif length_data <= 0xffff:
    return OP_PUSHDATA2 + length_data.to_bytes(2, byteorder='little')  # OP_PUSHDATA2 format
  else:
    return OP_PUSHDATA4 + length_data.to_bytes(4, byteorder='little')  # OP_PUSHDATA4 format

def construct_output_block(outputs):
  output_block = b''

  for data in outputs:
    dest, amount = data

    # Real recipient
    if amount:
      OP_DUP = b'v'
      OP_HASH160 = b'\xa9'
      OP_PUSH_20 = b'\x14'
      OP_EQUALVERIFY = b'\x88'
      OP_CHECKSIG = b'\xac'
      script = (OP_DUP + OP_HASH160 + OP_PUSH_20 + address_to_public_key_hash(dest) + OP_EQUALVERIFY + OP_CHECKSIG)
      output_block += amount.to_bytes(8, byteorder='little')

    # Blockchain storage
    else:
      OP_FALSE = b'\00'
      OP_RETURN = b'\x6a'
      script = OP_FALSE + OP_RETURN + get_op_pushdata_code(dest) + dest
      output_block += b'\x00\x00\x00\x00\x00\x00\x00\x00'

    # Script length in wiki is "Var_int" but there's a note of "modern BitcoinQT" using a more compact "CVarInt"
    output_block += int_to_varint(len(script))
    output_block += script

  return output_block

def hex_to_bytes(hexed):
  if len(hexed) & 1:
      hexed = '0' + hexed
  return bytes.fromhex(hexed)

def bytes_to_hex(bytestr, upper=False):
  return hexlify(bytestr).decode()


def construct_input_block(inputs):
  SEQUENCE = 0xffffffff.to_bytes(4, byteorder='little')

  input_block = b''
  sequence = SEQUENCE

  for txin in inputs:
      input_block += (
          txin.txid +
          txin.txindex +
          txin.script_len +
          txin.script +
          sequence
      )

  return input_block

def create_p2pkh_transaction(private_key, unspents, outputs):

  public_key = private_key.public_key
  public_key_len = len(public_key).to_bytes(1, byteorder='little')

  scriptCode = private_key.scriptcode
  scriptCode_len = int_to_varint(len(scriptCode))

  VERSION_1 = 0x01.to_bytes(4, byteorder='little')
  version = VERSION_1
  LOCK_TIME = 0x00.to_bytes(4, byteorder='little')
  lock_time = LOCK_TIME
  # sequence = SEQUENCE
  HASH_TYPE = 0x41.to_bytes(4, byteorder='little')
  hash_type = HASH_TYPE
  input_count = int_to_varint(len(unspents))
  output_count = int_to_varint(len(outputs))

  output_block = construct_output_block(outputs)

  # Optimize for speed, not memory, by pre-computing values.
  inputs = []
  for unspent in unspents:
      txid = hex_to_bytes(unspent.txid)[::-1]
      txindex = unspent.txindex.to_bytes(4, byteorder='little')
      amount = unspent.amount.to_bytes(8, byteorder='little')

      inputs.append(TxIn('', 0, txid, txindex, amount))

  SEQUENCE = 0xffffffff.to_bytes(4, byteorder='little')
  hashPrevouts = double_sha256(b''.join([i.txid+i.txindex for i in inputs]))
  hashSequence = double_sha256(b''.join([SEQUENCE for i in inputs]))
  hashOutputs = double_sha256(output_block)

  # scriptCode_len is part of the script.
  for i, txin in enumerate(inputs):
    to_be_hashed = (
        version +
        hashPrevouts +
        hashSequence +
        txin.txid +
        txin.txindex +
        scriptCode_len +
        scriptCode +
        txin.amount +
        SEQUENCE +
        hashOutputs +
        lock_time +
        hash_type
    )
    hashed = sha256(to_be_hashed)  # BIP-143: Used for Bitcoin SV

    # signature = private_key.sign(hashed) + b'\x01'
    signature = private_key.sign(hashed) + b'\x41'

    script_sig = (
        len(signature).to_bytes(1, byteorder='little') +
        signature +
        public_key_len +
        public_key
    )

    inputs[i].script = script_sig
    inputs[i].script_len = int_to_varint(len(script_sig))

  return bytes_to_hex(
    version +
    input_count +
    construct_input_block(inputs) +
    output_count +
    output_block +
    lock_time
  )

def get_fee(speed):
  if speed == 'fast':
    return 2
  elif speed == 'medium':
    return 1
  elif speed == 'slow':
    return 0.5
  else:
    raise ValueError('Invalid speed argument.')

def int_to_varint(val):
  if val < 253:
    return val.to_bytes(1, 'little')
  elif val <= 65535:
    return b'\xfd'+val.to_bytes(2, 'little')
  elif val <= 4294967295:
    return b'\xfe'+val.to_bytes(4, 'little')
  else:
    return b'\xff'+val.to_bytes(8, 'little')

def get_op_return_size(message):
  OP_FALSE = b'\00'
  OP_RETURN = b'\x6a'
  # calculate op_return size for each individual message
  op_return_size = (
    8  # int64_t amount 0x00000000
    + len(OP_FALSE + OP_RETURN)  # 2 bytes
    + len(get_op_pushdata_code(message))  # 1 byte if <75 bytes, 2 bytes if OP_PUSHDATA1...
    + len(message)  # Max 220 bytes at present
  )
  # "Var_Int" that preceeds OP_RETURN - 0xdf is max value with current 220 byte limit (so only adds 1 byte)
  op_return_size += len(int_to_varint(op_return_size))
  return op_return_size

def estimate_tx_fee(n_in, compressed, op_return_size):
  n_out = 1
  satoshis = get_fee('slow')
  if not satoshis:
    return 0
  estimated_size = (
    4 +  # version
    n_in * (148 if compressed else 180)
    + len(int_to_varint(n_in))
    + n_out * 34  # excluding op_return outputs, dealt with separately
    + len(int_to_varint(n_out))
    + op_return_size  # grand total size of op_return outputs(s) and related field(s)
    + 4  # time lock
  )
  return math.ceil(estimated_size * satoshis)

def chunk_data(data, size):
  return (data[i:i + size] for i in range(0, len(data), size))

def sanitize_tx_data(unspents, leftover, message, compressed):
  outputs = deque([])

  if not unspents:
    raise ValueError('Transactions must have at least one unspent.')

  # Temporary storage so all outputs precede messages.
  messages = deque()
  total_op_return_size = 0

  MESSAGE_LIMIT = 100000
  message_chunks = chunk_data(message, MESSAGE_LIMIT)
  for message in message_chunks:
    messages.appendleft((message, 0))
    total_op_return_size += get_op_return_size(message)

  # Include return address in fee estimate.
  # calculated_fee is in total satoshis.
  calculated_fee = estimate_tx_fee(len(unspents), compressed, total_op_return_size)
  total_out = calculated_fee
  unspents = unspents.copy()
  total_in = sum(unspent.amount for unspent in unspents)

  remaining = total_in - total_out

  # If the uxto less than dust (546) the miner will not relay that tx, even the service can successful return.
  # Here we put all the remnant (<546) to the miner in this case.
  # We could adjust here when new dust agreement reached in future.
  DUST = 546
  if remaining > DUST:
    outputs.append((leftover, remaining))
  elif remaining < 0:
    raise InsufficientFunds('Balance {} is less than {} (including fee).'.format(total_in, total_out))

  outputs.extendleft(messages)

  return unspents, list(outputs)

# real
msg = 'hi'.encode('utf-8')
key = Key('')
unspents, outputs = sanitize_tx_data(
  get_unspents(key.address),
  key.address,
  message=msg,
  compressed=key.is_compressed()
)
tx_hex = create_p2pkh_transaction(key, unspents, outputs)
txid = send(tx_hex)
print("https://blockchair.com/bitcoin-sv/transaction/{}".format(txid))

# regtest
# msg = 'xyū'.encode('utf-8')
# key = Key('cRVFvtZENLvnV4VAspNkZxjpKvt65KC5pKnKtK7Riaqv5p1ppbnh')
# _unspents = [ Unspent(amount=5000000000, confirmations=120, txid="4bc41432979746dbd6c613dc5b2a2c1234ecc6a5bf3b48d108b4ecba90ea43fe", txindex=0) ]
# unspents, outputs = sanitize_tx_data(
#   _unspents,
#   key.address,
#   message=msg,
#   compressed=key.is_compressed()
# )
# tx_hex = create_p2pkh_transaction(key, unspents, outputs)
# print(tx_hex)