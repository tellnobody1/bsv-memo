from bitsv import Key
from bitsv.transaction import create_p2pkh_transaction
from collections import deque
from api import get_unspents, send
import math

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
  op_return_size = (
    8  # int64_t amount 0x00000000
    + len(OP_FALSE + OP_RETURN)  # 2 bytes
    + len(message)  # Unsure if Max size will be >220 bytes due to extra OP_PUSHDATA codes...
  )
  # "Var_Int" that preceeds OP_RETURN - 0xdf is max value with current 220 byte limit (so only adds 1 byte)
  op_return_size += len(int_to_varint(op_return_size))
  return op_return_size

def estimate_tx_fee(n_in, n_out, satoshis, compressed, op_return_size):
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

def sanitize_tx_data(unspents, leftover, message, compressed):
  if not unspents:
    raise ValueError('Transactions must have at least one unspent.')

  MESSAGE_LIMIT = 100000
  if len(message) >= MESSAGE_LIMIT:
    raise ValueError("Currently cannot exceed 100000 bytes with custom_pushdata.")

  # Include return address in fee estimate.
  # calculated_fee is in total satoshis.
  num_outputs = 1
  fee = get_fee('slow')
  total_op_return_size = get_op_return_size(message)
  calculated_fee = estimate_tx_fee(len(unspents), num_outputs, fee, compressed, total_op_return_size)
  unspents = unspents.copy()
  total_in = sum(unspent.amount for unspent in unspents)

  remaining = total_in - calculated_fee

  outputs = deque([])
  outputs.append((message, 0))

  # If the uxto less than dust (546) the miner will not relay that tx, even the service can successful return.
  # Here we put all the remnant (<546) to the miner in this case.
  # We could adjust here when new dust agreement reached in future.
  DUST = 546
  if remaining > DUST:
    outputs.append((leftover, remaining))
  elif remaining < 0:
    raise InsufficientFunds('Balance {} is less than {} (including fee).'.format(total_in, total_out))

  return unspents, list(outputs)

msg = 'x'.encode('utf-8')
key = Key('')
unspents, outputs = sanitize_tx_data(
  get_unspents(key.address),
  key.address,
  message=msg,
  compressed=key.is_compressed()
)
tx_hex = create_p2pkh_transaction(key, unspents, outputs, custom_pushdata=True)
txid = send(tx_hex)
print("https://blockchair.com/bitcoin-sv/transaction/{}".format(txid))
