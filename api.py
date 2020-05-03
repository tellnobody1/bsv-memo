import json
import requests
from bitsv.network.meta import Unspent

def get_unspents(address):
  r = requests.get("https://bchsvexplorer.com/api/addr/{}/utxo".format(address), timeout=30)
  r.raise_for_status()
  utxos = [
    Unspent(amount=utxo['satoshis'],
            confirmations=utxo['confirmations'],
            txid=utxo['txid'],
            txindex=utxo['vout'])
    for utxo in r.json()
  ]
  return sorted(utxos, key=lambda utxo: (-utxo.confirmations, utxo.amount))

def send(tx_hex):
  r = requests.post(
    'https://api.whatsonchain.com/v1/bsv/main/tx/raw',
    data=json.dumps({'txhex': tx_hex}),
    headers={
      'Content-Type': 'application/json'
    },
  )
  r.raise_for_status()
  return r.text.strip('"')
