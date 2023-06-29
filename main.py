import json
import random
import csv
from web3 import Web3
import requests
from loguru import logger
import time
from tqdm import tqdm
from eth_abi import encode
def check_status_tx(address, w3, tx_hash):
    logger.info(f'{address} - жду подтверждения транзакции  https://bscscan.com/tx/{w3.to_hex(tx_hash)}...')

    start_time = int(time.time())
    while True:
        current_time = int(time.time())
        if current_time >= start_time + 100:
            logger.info(
                f'{address} - транзакция не подтвердилась за 100 cекунд, начинаю повторную отправку...')
            return 0
        try:
            status = w3.eth.get_transaction_receipt(tx_hash)['status']
            if status == 1:
                return status
            time.sleep(1)
        except Exception as error:
            time.sleep(1)

def sleep_indicator(sec):
    for i in tqdm(range(sec), desc='жду', bar_format="{desc}: {n_fmt}c /{total_fmt}c {bar}", colour='green'):
        time.sleep(1)

def write_to_csv(filename, key, address, result):
    with open(filename, 'a', newline='') as file:
        writer = csv.writer(file)

        if file.tell() == 0:
            writer.writerow(['key', 'address', 'result'])

        writer.writerow([key, address, result])
def get_proof(address):
    headers = {
        'authority': 'graphigo.prd.space.id',
        'accept': '*/*',
        'accept-language': 'ru,en;q=0.9',
        'content-type': 'application/json',
        'origin': 'https://space.id',
        'sec-ch-ua': '"Chromium";v="112", "YaBrowser";v="23", "Not:A-Brand";v="99"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 YaBrowser/23.5.3.904 Yowser/2.5 Safari/537.36',
    }

    json_data = {
        'operationName': 'AirdropMerkleProof',
        'variables': {
            'addr': address.lower(),
        },
        'query': 'query AirdropMerkleProof($addr: String!) {\n  AirdropMerkleProof(addr: $addr) {\n    exists\n    addr\n    idx\n    amount\n    proof\n    __typename\n  }\n}',
    }

    try:
        response = requests.post('https://graphigo.prd.space.id/query', headers=headers, json=json_data)
        if response.status_code == 200:
            data = json.loads(response.text)
            if data['data']['AirdropMerkleProof']['exists']:
                return dict(data['data']['AirdropMerkleProof'])
            else:
                logger.error(f'кошелек {address} - не элиджбл...')
                return False
    except Exception as e:
        logger.error(f'{address} - {e}...')


def claimer(key, delay):
    address_ = Web3.to_checksum_address('0x9466a0E427b851963F092DcE5a26a9D9707198e7')
    abi = '[{"inputs":[{"internalType":"uint256","name":"index","type":"uint256"},{"internalType":"address","name":"account","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"},{"internalType":"bytes32[]","name":"proof","type":"bytes32[]"}],"name":"claim","outputs":[],"stateMutability":"nonpayable","type":"function"}]'
    w3 = Web3(Web3.HTTPProvider('https://bscrpc.com'))
    account = w3.eth.account.from_key(key)
    address = account.address
    claim = w3.eth.contract(address=address_, abi=abi)
    data = get_proof(address)
    if data:
        index = data['idx']
        amount = int(data['amount'])
        addr = Web3.to_checksum_address(data['addr'])
        proof = data['proof']
    else:
        return address, 'error'

    try:
        tx = claim.functions.claim(index, addr, amount, proof).build_transaction({
            'from': address,
            'nonce': w3.eth.get_transaction_count(address),
            'gas': claim.functions.claim(index, addr, amount, proof).estimate_gas({
                'from': address,'nonce': w3.eth.get_transaction_count(address)}),
            'gasPrice': w3.eth.gas_price
        })
        sign = account.sign_transaction(tx)
        hash_ = w3.eth.send_raw_transaction(sign.rawTransaction)
        status = check_status_tx(address, w3, hash_)
        if status == 1:
            logger.success(
                f'{address}- успешно заклеймил {amount/10**18} ID : https://bscscan.com/tx/{w3.to_hex(hash_)}...')
            sleep_indicator(random.randint(delay[0], delay[1]))
            return address, 'success'
        else:
            logger.info(f'{address} - пробую клеймить еще раз...')
            return claimer(key, delay)

    except Exception as e:
        logger.error(f'{address} - {e}')
        return address, 'error'


def main():
    with open("keys.txt", "r") as f:
        keys = [row.strip() for row in f]
        random.shuffle(keys)
    print(f'\n{" " * 32}автор - https://t.me/iliocka{" " * 32}\n')
    logger.info('Начинаю клеймить токены...')
    delay = (0, 100)
    for key in keys:
        res = claimer(key, delay)
        write_to_csv('data.csv', key, *res)
    logger.success('Успешный клейминг...')
    print(f'\n{" " * 32}автор - https://t.me/iliocka{" " * 32}\n')
    print(f'\n{" " * 32}donate - EVM 0xFD6594D11b13C6b1756E328cc13aC26742dBa868{" " * 32}\n')
    print(f'\n{" " * 32}donate - trc20 TMmL915TX2CAPkh9SgF31U4Trr32NStRBp{" " * 32}\n')


if __name__ == '__main__':
    main()