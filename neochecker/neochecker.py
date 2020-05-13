import tqdm
import json
import requests
import argparse
from neochecker.setup_logger import *
from fake_useragent import UserAgent
from multiprocessing.dummy import Pool
from multiprocessing import cpu_count
from tenacity import retry, retry_if_exception_type, wait_random, stop_after_attempt


class RetryException(Exception):

    def __init__(self):

        pass


class NeoScanner(object):

    def __init__(self, **kwargs):

        self._input_list = kwargs.get('input_list')
        self._output_file = kwargs.get('output_file')
        self._proxy = kwargs.get('proxy')
        self._threads = kwargs.get('threads')

        self._api_base_url = "https://api.neoscan.io/api/main_net/v1/get_balance/"

    @retry(retry=retry_if_exception_type(RetryException), wait=wait_random(30, 60), stop=stop_after_attempt(10))
    def get_balance(self, addr):

        addr = addr.rstrip("\n")
        url = self._api_base_url + addr
        ua = UserAgent()

        headers = {
            "User-Agent": ua.chrome
        }

        try:
            if self._proxy:
                proxies = dict(
                    http=self._proxy,
                    https=self._proxy
                )

                req = requests.get(url, headers=headers, proxies=proxies)

            else:
                req = requests.get(url, headers=headers)

        except requests.exceptions.ProxyError as e:

            logger.debug(f"Proxy error when checking {addr}. Error: {e}")
            raise RetryException

        except requests.exceptions.ConnectionError as e:

            logger.debug(f"Connection error when checking {addr}. Error: {e}")
            raise RetryException

        if req.status_code != 200:
            logger.debug(f"Got a non-200 status code when checking {addr}. Retrying.")
            raise RetryException

        try:
            # Create the search context.
            ctx = json.loads(req.content.decode('utf-8'))
        except json.JSONDecodeError as e:
            logger.debug(f"Issue decoding JSON for {addr}. Error: {e}")
            raise RetryException

        return ctx

    def run(self):

        p = Pool(processes=int(self._threads))

        rf = open(self._input_list, 'r')
        if self._output_file:
            wf = open(self._output_file, 'w')
        addrs = rf.readlines()

        result_totals = {
            "NEO": []
        }

        for _ in tqdm.tqdm(p.imap_unordered(self.get_balance, addrs), total=len(addrs)):

            logger.debug(f"Got a result: {_}.")
            if self._output_file:
                wf.write(json.dumps(_) + "\n")

            balance = _.get('balance')
            for asset in balance:
                amount = asset.get("ammount")
                asset_name = asset.get("asset_symbol")
                if asset.get("amount") > 0:
                    logger.log(LVL.SUCCESS, f"[$] Got a balance of {amount} {asset_name} in {_.get('address')}")
                    if asset_name in result_totals:
                        result_totals[asset_name].append(amount)
                    else:
                        # Create they key if it doesn't exist.
                        result_totals[asset_name] = []
                        result_totals[asset_name].append(amount)

        for key, val in result_totals.items():
            summed = sum(val)
            if summed > 0:
                logger.log(LVL.SUCCESS, f"[$] Found a total of {summed} {key} in all checked wallets.")
        logger.debug(f"Here's all results: {result_totals}")

        rf.close()
        wf.close()


def main():

    parser = argparse.ArgumentParser("Scan NEO wallets.")
    # Switched args
    parser.add_argument("-v", dest="verbose", action='count', default=0, help="Enable verbose output.")
    parser.add_argument("-iL", "--input-list", action="store", required=True, help="Input list of <ticker:address>.")
    parser.add_argument("-o", "--output", action="store", help="JSON file containing outputs.")
    parser.add_argument("-p", "--proxy", action="store", help="Proxy to use. EX: https://user:pass@127.0.0.1:9050")
    parser.add_argument("-t", "--threads", action="store", default=cpu_count(),
                        help="Number of threads to use. Due to rate limiting, more isn't necessarily better.")

    args = parser.parse_args()

    if args.verbose:
        if args.verbose == 1:
            level = LVL.VERBOSE
        elif args.verbose == 2:
            level = LVL.DEBUG
        elif args.verbose == 3:
            level = LVL.SPAM
        else:
            level = LVL.NOTSET
    else:
        level = LVL.INFO
    # Init logging.
    setup(level=level)

    scanner = NeoScanner(
        input_file=args.input_list,
        output_file=args.output,
        threads=args.threads,
        proxy=args.proxy
    )

    scanner.run()


if __name__ == "__main__":

    main()
