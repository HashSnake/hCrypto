# HashCrypto Public Application 

[![Build Status](https://travis-ci.org/joemccann/dillinger.svg?branch=master)](https://travis-ci.org/joemccann/dillinger)

Decryptor cold wallets data, from extension Metamask, Ronin, Binance, Brawe, etc.
best decrypter via python, so fast work.


- Decrypt vault data from `0000.log` file.
- Return `mnemonic` , derivation key, description
- Many options

## Installation

Python requires [Python.org](https://www.python.org/) v.3.7

Install the dependencies and devDependencies and start the server.

```sh
sudo apt update && apt upgrade
apt install python3 && apt install python3-pip
pip install -r requirements.txt
```
Example hash\vault to decrypt

```sh
{"data": "M5YTg9f1PP62HlCyuX1l2Bq+OnwgvjhoVc+FklxWqBSeHg4ihGypUjUtS5T3M/MHPsh5GATR/iKzdvhHdFGm5moqqhITU5RTZUuqDOdy2MOZh++moX/vwgyUiz9HS9OPb0Y5su4FGu2emhEw8X7Eb0kfOCCt8Q8iNjR8lHCQPHStiupd/MA05lV48bC/INStN7nDr1WDa+0TFpNGmVE9KeQe9xBtBm4Uw/JFWXZ9r12dua2DURkczPvqNrftxohPRmszYZ83psGSMpAAWqWcLzal3TOCZElB6SdFTLxBO9G1NXPC+u8vig+nxwPJKhBSkRvVqHOe4ncjkCjVM55+S7/J0QE9c/EAZS47WXOHRg+579UYPW79onmJkH9i6/F6NHU/FfMrzGmqlPys9kRp4eLfpqpnxOj72E1sdHodSfgksE6EzK1C6k5naQGOqIInPjllKP5tBi+oap8iLiFFGp87DMvvSnkdDyPfc42XxFemJa63/GTinTUzR6Klg1aC5RCJS8fyk24VUnH2zSIWZNgdqC8P49P5lWqXCN6Tkysf5sgGLoSwxrAHFJmUDLZEZajRCQe/6yzbuOfbg7hqubWco/J+EO1AwrwvhsoBwtX6QTZqF9jManWLqAslogAiaWmZeOxNjXdYpF1Q5cy4IDOS5miv7Xz+hGnB4lUSBN9VZz+cdJrVBNM3Xa5HDkS+fzGzMa95oG2obXnWvQrm1Ct1+kclt+jG7jGeLkc6XwxYgLabHGc0wSAVMLhNYB9Mk+97", "iv": "6CD2HmS+Zu32dz4BMbyICg==", "salt": "TkHQ2jqz2CYYbeAasJTJJX4oU+LoXstTdRxefxaSC/g="}
```
Example python code:

```python
from hashDecrypt import hdec
VAULT = '{"data": "M5YT....9Mk+97", "iv": "6CD2Hm...Cg==", "salt": "TkHQ....xaSC/g="}'
PASSWORD = "Awerawer22"
w = hdec()
obj = w.decrypt(PASSWORD, VAULT)
print(obj)
```

Example output:
```sh
{'status': True, 'message': None, 'result': [{'type': 'HD Key Tree', 'data': {'mnemonic': crystal report cupboard slot under spare remember ostrich cannon arrest twelve stamp, 'numberOfAccounts': 1, 'hdPath': "m/44'/60'/0'/0"}}, {'type': 'Ledger Hardware', 'data': {'hdPath': "m/44'/60'/0'", 'accounts': [], 'accountDetails': {}, 'bridgeUrl': 'https://metamask.github.io/eth-ledger-bridge-keyring', 'implementFullBIP44': False}}]}
```




## License

MIT

**Free Software, Hell Yeah!**

[//]: # (These are reference links used in the body of this note and get stripped out when the markdown processor does its job. There is no need to format nicely because it shouldn't be seen. Thanks SO - http://stackoverflow.com/questions/4823468/store-comments-in-markdown-syntax)

   [dill]: <https://github.com/joemccann/dillinger>
   [git-repo-url]: <https://github.com/joemccann/dillinger.git>
   [john gruber]: <http://daringfireball.net>
   [df1]: <http://daringfireball.net/projects/markdown/>
   [markdown-it]: <https://github.com/markdown-it/markdown-it>
   [Ace Editor]: <http://ace.ajax.org>
   [node.js]: <http://nodejs.org>
   [Twitter Bootstrap]: <http://twitter.github.com/bootstrap/>
   [jQuery]: <http://jquery.com>
   [@tjholowaychuk]: <http://twitter.com/tjholowaychuk>
   [express]: <http://expressjs.com>
   [AngularJS]: <http://angularjs.org>
   [Gulp]: <http://gulpjs.com>

   [PlDb]: <https://github.com/joemccann/dillinger/tree/master/plugins/dropbox/README.md>
   [PlGh]: <https://github.com/joemccann/dillinger/tree/master/plugins/github/README.md>
   [PlGd]: <https://github.com/joemccann/dillinger/tree/master/plugins/googledrive/README.md>
   [PlOd]: <https://github.com/joemccann/dillinger/tree/master/plugins/onedrive/README.md>
   [PlMe]: <https://github.com/joemccann/dillinger/tree/master/plugins/medium/README.md>
   [PlGa]: <https://github.com/RahulHP/dillinger/blob/master/plugins/googleanalytics/README.md>
