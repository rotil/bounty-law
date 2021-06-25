#!/usr/bin/env python3

#https://www.offensity.com/de/blog/just-another-recon-guide-pentesters-and-bug-bounty-hunters/
#pip install validators
#go get github.com/hakluke/hakrawler
#GO111MODULE=auto go get -u -v github.com/projectdiscovery/subfinder/cmd/subfinder  install subfinder
#subfinder -d $domain -nW -o "gather-online.txt" -rL dns.txt > /dev/null 2>&1
#shuffledns -d example.com -list example.com-subdomains.txt -r resolvers.txt   or Resolving Subdomains
#shuffledns -d hackerone.com -w wordlist.txt -r resolvers.txt for Bruteforcing Subdomains
#shuffledns -d indeed.com -w subdns -r dns.txt -t 5000 -o allsub.txt
#subfinder -d indeed.com -nW -o "gather-online.txt" -rL dns.txt  subfinder

#word list
#gau royalpardazco.ir| unfurl format "%s://%d%:%P%p" | grep -iE "\.js$" | sort -u >gaujs.txt
#hakrawler -js -url http://royalpardazco.ir -plain -depth 2 -scope strict -insecure > hakrawl1.txt
#cat hakrawl1.txt| unfurl format "%s://%d%:%P%p" | grep -iE "\.js$" | sort -u > hakrawler.txt
#cat gaujs.txt hakrawler.txt | sort -u > gauhak.txt
#ffuf -w $wordlist -u $jsdir/FUZZ -e .js,.min.js -mc 200,304 -o $TMPDIR/ffuf.json -s -t 100 > /dev/null
#cat $TMPDIR/ffuf.json | jq -r ".results[].url" | grep "\.js" | unfurl format "%s://%d%:%P%p" | grep -iE "\.js$" | sort -u >$TMPDIR/ffuf_tmp.txt
#    cat $TMPDIR/ffuf_tmp.txt >> $TMPDIR/ffuf.txt
#https://github.com/ProjectAnte/dnsgen


#cat backblaze.com.http.txt|aquatone -chrome-path /home/wall3/Desktop/bounty-law/tools/chrome-linux/chrome -ports large
#subjack -w alltargets.txt -t 100 -timeout 30 -o results.txt -ssl


import sys
import validators
import requests
import re
import os.path
from os import path
import subprocess



print("  _                               _               _                      ")
print(" | |                             | |             | |                     ")
print(" | |__     ___    _   _   _ __   | |_   _   _    | |   __ _  __      __  ")
print(" | '_ \   / _ \  | | | | | '_ \  | __| | | | |   | |  / _` | \ \ /\ / /  ")
print(" | |_) | | (_) | | |_| | | | | | | |_  | |_| |   | | | (_| |  \ V  V /   ")
print(" |_.__/   \___/   \__,_| |_| |_|  \__|  \__, |   |_|  \__,_|   \_/\_/    ")
print("                                         __/ |                           ")
print("                                        |___/                            ")



# Count the arguments
arguments = len(sys.argv) - 1

# Output argument-wise
position = 1
domain=""
ipflag=""
gitflag=""
amassflag=""
subfinderflag=""
shufflednsflag=""
aquatoneflag=""
jswflag=""
while (arguments >= position):
    #print ("Parameter %i: %s" % (position, sys.argv[position]))
    if (sys.argv[position])== "-d":
    	domain = sys.argv[(position+1)]
    elif(sys.argv[position])== "-ip":
    	ipflag=1
    elif(sys.argv[position])== "-sf":
    	subfinderflag=1
    elif(sys.argv[position])== "-am":
    	amassflag=1
    elif(sys.argv[position])== "-gh":
    	gitflag=1
    elif(sys.argv[position])== "-sh":
    	shufflednsflag=1
    elif(sys.argv[position])== "-aq":
    	aquatoneflag=1
    elif(sys.argv[position])== "-jsw":
    	jswflag=1
    elif (sys.argv[position])== "-h":
    	print("usage bounty-law.py -d domain -gh -ip -sf -am -sh -aq -jsw")
    position = position + 1


# amass subfinder massdns

def github( domain ):   #Github python generated search links (from hunter.sh)
	print(" ************ Github Dork Links (must be logged in) *******************")
	print("")
	dork = ["password","npmrc_auth","dockercfg","pemprivate","id_rsa","aws_access_key_id","s3cfg","htpasswd","git-credentials","bashrcpassword","sshd_config","xoxpORxoxbORxoxa","SECRET_KEY","client_secret","sshd_config","github_token","api_key","FTP","app_secret","passwd","s3.yml",".exs","beanstalkd.yml","deploy.rake","mysql","credentials","PWD","deploy.rake",".bash_history",".sls","secrets","composer.json"]
	for item in dork:
		print("\n",item)
		print("https://github.com/search?q=%22"+domain+"%22+"+item+"&type=Code","")
	return



def createfolder( domain ):   #create folder
	MYDIR = (domain)
	CHECK_FOLDER = os.path.isdir(MYDIR)

	# If folder doesn't exist, then create it.
	if not CHECK_FOLDER:
	    os.makedirs(MYDIR)
	    print("created project folder : ", MYDIR)

	else:
	    print(MYDIR, "project already exists.")



def fresh_resolvers():   #fresh-resolvers
	print("\n ************ GET fresh-resolvers *******************")
	try:
		output = subprocess.getoutput("wget https://raw.githubusercontent.com/BonJarber/fresh-resolvers/main/resolvers.txt -O dns.txt")

	except:
		print("\n GET fresh-resolvers error.\n")






def asnlookup( domain ):   #ASNLookup can be used to retrieve information in JSON format.http://asnlookup.com/api/lookup?org=
	print("\n ************ ASNLookup get ip ranges of company *******************")
	company=domain.split(".", 1)[0]
	iprange = requests.get("http://asnlookup.com/api/lookup?org="+company)
	data = iprange.json()
	if data: 
		for ip in data:
			print(ip)
		try:
			os.stat(domain+"/"+"ip.txt")# file exists
			file = open(domain+"/"+"ip.txt", "r")
			lastip = file.readline() 
			list_difference = []

			for item in data:
  				if item not in lastip:
  					list_difference.append(item)
			print(list_difference)
		except:
		    file = open(domain+"/"+"ip.txt", "w")
		    file.write(str(data))
		    file.close()
	else:
		print("\n can not find the ip range.\n")


def subfinder( domain ):   #subfinder enum
	print("\n ************ subfinder enum using api *******************")
	first_subfinder=0
	try:
		if os.stat(domain+"/"+domain+".subfinder.sub.txt"):
			print("subfinder already exists.")

	except:
		print("\n first time subfinder.\n")
		first_subfinder=1
		if first_subfinder:
			try:
				#print(("subfinder -d "+domain+" -nW -rL dns.txt -o "+domain+"/"+domain+".subfinder.sub"))
				output = subprocess.getoutput("subfinder -d "+domain+" -recursive -nW -rL dns.txt -o "+domain+"/"+domain+".subfinder.sub.txt")
			except:
				print("\n error in subfinder.\n")
		else:
			print("\n error in subfinder.\n")







def amass( domain ):   #amass enum
	print("\n ************ amass enum max-dns-queries *******************")
	first_amass=1
	try:
		list_difference_domain = []
		if os.stat(domain+"/"+domain+".sub"):
			with open(domain+"/"+domain+".sub.all", "r") as file:
				lastdomain = file.readlines()
				file.close()
				#print(lastdomain)
				os.remove(domain+"/"+domain+".sub")
	except:
		print("\n first time amass amass.\n")
		first_amass=0

	# print(("amass enum -rf dns.txt -max-dns-queries 20000 -d "+domain+" -o "+domain+".sub"))
	output = subprocess.getoutput("amass enum -rf dns.txt -max-dns-queries 5000 -d "+domain+" -o "+domain+"/"+domain+".sub")
	#outputall = subprocess.getoutput("amass db -d "+domain+" -names -o "+domain+"/"+domain+".sub.all")
	if first_amass:
 # 		#print(output)
		try:
			print("try")
			with open(domain+"/"+domain+".sub", "r") as new_file:
				new_domain = new_file.readlines()
				for domain in new_domain:
					if domain not in lastdomain:
						list_difference_domain.append(domain)
				print("diff",list_difference_domain)
		except:
			print("\n error in amass.\n")
	else:
		print(output)


#shuffledns -d indeed.com -w subdns -r dns.txt -t 5000 -o allsub.txt
def shuffledns( domain ):   #shuffledns enum using massdns
	print("\n ************ shuffledns enum using massdns *******************")
	first_shuffledns=0
	second_shuffledns=0
	third_shuffledns=0

	if not os.path.exists(domain+"/"+domain+".shuffledns1.sub"):
		print("\n first time shuffledns.\n")
		first_shuffledns=1
		if first_shuffledns:

			try:
				output = subprocess.getoutput("shuffledns -d "+domain+" -w subdns -r dns.txt -t 2000 -o "+domain+"/"+domain+".shuffledns1.sub")
			except:
				print("\n error in shuffledns 1+.\n")
	else:
		print("\n first time shuffledns already exists.\n")

	if  not os.path.exists(domain+"/"+domain+".shuffledns2.sub.all"):
		print("\n second  time shuffledns.\n")
		second_shuffledns=1
		if second_shuffledns:
			try:
				subprocess.getoutput("cd "+domain+";cat *sub* |sort -u > "+domain+".shuffledns2.sub.all")
				if os.stat(domain+"/"+domain+".shuffledns2.sub.all"):
					with open(domain+"/"+domain+".shuffledns2.sub.all", "r") as file:
						list_all_domain = file.readlines()
						file.close()
						for dom in list_all_domain:
							output = subprocess.getoutput("shuffledns -d "+dom+" -w subdns -r dns.txt -t 2000 -o "+domain+"/"+dom+".shuffledns2.sub")
			except:
				print("\n error in second  time shuffledns.\n")
		else:
			print("\n error in shuffledns 2.\n")

	if  not os.path.exists(domain+"/"+domain+".shuffledns3.sub.all"):
		print("\n third  time shuffledns.\n")
		third_shuffledns=1
		if third_shuffledns:
			try:
				subprocess.getoutput("cd "+domain+";cat *shuffledns2* |sort -u > "+domain+".shuffledns3.sub.all")
				if os.stat(domain+"/"+domain+".shuffledns3.sub.all"):
					with open(domain+"/"+domain+".shuffledns3.sub.all", "r") as file:
						list_all_domain = file.readlines()
						file.close()
						for dom in list_all_domain:
							output = subprocess.getoutput("shuffledns -d "+dom+" -w subdns -r dns.txt -t 1000 -o "+domain+"/"+domain+".shuffledns3.sub")
							subprocess.getoutput("cd "+domain+";cat *sub* |sort -u > "+domain+".sub.all")
						#	shuffledns -d example.com -list example.com-subdomains.txt -r resolvers.txt
						output = subprocess.getoutput("shuffledns -d "+domain+" -list "+domain+"/"+domain+".sub.all -r dns.txt -t 1000 -o "+domain+"/"+domain+".resolve.sub")
						print("\n resolve domain for "+domain+" shuffledns is ready.\n")
			except:
				print("\n error in third  time shuffledns.\n")
		else:
			print("\n error in shuffledns 3.\n")

def aquatone( domain ):   #aquatone httpx
	print("\n ************ aquatone httpx *******************")
	try:
		if os.stat(domain+"/"+domain+".resolve.sub"):
			MYDIR = ("/aquatone")
			CHECK_FOLDER = os.path.isdir(domain+MYDIR)
			if not CHECK_FOLDER:
				os.makedirs(domain+MYDIR)
				print("created project folder : ", domain+MYDIR)
			else:
				print(domain+MYDIR, "aquatone already exists.")

			output = subprocess.getoutput("cd "+domain+";cat *resolve* |httpx -o ""aquatone/"+domain+".httpx.all")
			print(output)
			#cat backblaze.com.http.txt|aquatone -chrome-path /home/wall3/Desktop/bbt/bounty-law/tools/chrome-linux/chrome -ports large
			output = subprocess.getoutput("cd "+domain+"/aquatone"";cat *httpx.all*|sort -u|aquatone -chrome-path /home/wall3/Desktop/bbt/bounty-law/tools/chrome-linux/chrome -ports xlarge")
			print(output)


	except IndexError as e:
		print("\n first time aquatone.\n")
		print(e)
		first_amass=0


#word list
#hakrawler -js -url http://royalpardazco.ir -plain -depth 2 -scope strict -insecure > hakrawl1.txt
#cat hakrawl1.txt| unfurl format "%s://%d%:%P%p" | grep -iE "\.js$" | sort -u > hakrawler.txt
#cat gaujs.txt hakrawler.txt | sort -u > gauhak.txt
#ffuf -w $wordlist -u $jsdir/FUZZ -e .js,.min.js -mc 200,304 -o $TMPDIR/ffuf.json -s -t 100 > /dev/null
#cat $TMPDIR/ffuf.json | jq -r ".results[].url" | grep "\.js" | unfurl format "%s://%d%:%P%p" | grep -iE "\.js$" | sort -u >$TMPDIR/ffuf_tmp.txt
#    cat $TMPDIR/ffuf_tmp.txt >> $TMPDIR/ffuf.txt
#https://github.com/ProjectAnte/dnsgen

def jswfind( domain ):   #word with list js file
	print("\n ************ word with list js file *******************")
	try:
		#if not os.stat(domain+"/jsfile/"+domain+".gau.txt"):
			#os.stat(domain+"/""jsfile"".resolve.sub"
			MYDIR = ("/jsfile")
			path = os.path.abspath("scripthunter-wordlist.txt")
			getjswords = os.path.abspath("getjswords.py")
			CHECK_FOLDER = os.path.isdir(domain+MYDIR)
			if not CHECK_FOLDER:
				os.makedirs(domain+MYDIR)
				print("created project folder : ", domain+MYDIR)
			else:
				print(domain+MYDIR, "jsfile folder already exists.")
			#print(subprocess.getoutput("cd "+domain/jsfile+";gau domain |sort -u > ""gau"+domain+".txt")
			CHECK_FOLDER = os.path.isfile(domain+MYDIR+"/""gau."+domain+".txt")
			#print(CHECK_FOLDER)
			#print (not CHECK_FOLDER)
			#print("gau."+domain+".txt")
			if not CHECK_FOLDER:
				output = subprocess.getoutput("cd "+domain+"/jsfile"";gau "+domain+" |sort -u >gau."+domain+".txt")
			else:
				print(domain+MYDIR, "gau already exists.")
			print("try gau")
			output = subprocess.getoutput("cd "+domain+"/jsfile"";cat gau."+domain+".txt""|unfurl format "+"%s://%d%:%P%p""| grep -iE '\.js$'" "|deduplicate -sort >""js."+domain+".js.txt")
			print("try hakrawler")
			output = subprocess.getoutput("cd "+domain+"/jsfile"";hakrawler -js -url https://"+domain+" -plain -depth 2 -scope strict -insecure |sort -u >hakrawl."+domain+".js.txt")
			print(output)
			output = subprocess.getoutput("cd "+domain+"/jsfile"";cat *.js.txt | unfurl format ""%s://%d%:%P%p" "| grep -iE " "\.js$" "| sort -u >alljs."+domain+".txt")
			print("try ffuf")
			output = subprocess.getoutput("cd "+domain+"/jsfile"";ffuf -w "+path+" -u https://"+domain+"/FUZZ -e .js,.min.js -mc 200,304 -o ffuf.js.txt -s -t 100 > /dev/null")
			output = subprocess.getoutput("cd "+domain+"/jsfile"";cat ffuf.js.txt| jq -r "".results[].url" "| grep  " "\.js" " | unfurl format ""%s://%d%:%P%p"" | grep -iE ""\.js$""| sort -u >ffuf_tmp.js.txt")
			output = subprocess.getoutput("cd "+domain+"/jsfile"";cat *.js.txt | unfurl format ""%s://%d%:%P%p" "| grep -iE " "\.js$" "| sort -u |httpx -silent -status-code -mc 200 -content-type| grep javascript|cut -d ' ' -f 1 >alljs."+domain+".txt")
			print(output)
			output = subprocess.getoutput("cd "+domain+"/jsfile"";rm *.js.txt")
			print("try wordlist")
			print("python3 "+getjswords+" "+domain+"/jsfile/")
			output = subprocess.getoutput("python3 "+getjswords+" "+domain+"/jsfile/")
			print(output)
			# print(domain+"/jsfile/")
			# if os.stat(domain+"/jsfile/""alljs."+domain+".txt"):
			# 	with open(domain+"/jsfile/""alljs."+domain+".txt", "r") as file:
			# 		lastjs = file.readlines()
			# 		file.close()
			# 		for js in lastjs:
			# 			print(js)
			# 			print("python3 "+getjswords+" "+js+" "+domain+"/jsfile/")
			# 			output = subprocess.getoutput("cd "+domain+"/jsfile"";python3 "+getjswords+" "+js+"+" " "+domain+"/jsfile/")
			# 			print(output)
			# 			print(33)
			# 	output = subprocess.getoutput("cd "+domain+"/jsfile"";cat wordlist.txt|sort -u >jswordlist.txt")
			print(output)

#hakrawler -js -url http://royalpardazco.ir -plain -depth 2 -scope strict -insecure > hakrawl1.txt

	except (RuntimeError, TypeError, NameError):
		print("\n first time js word list.\n")
		#first_amass=0


	# MYDIR = (domain)
	# CHECK_FOLDER = os.path.isdir(MYDIR)

	# # If folder doesn't exist, then create it.
	# if not CHECK_FOLDER:
	#     os.makedirs(MYDIR)
	#     print("created project folder : ", MYDIR)

	# else:
	#     print(MYDIR, "project already exists.")



if (validators.domain(domain)) and (domain!=""):
	
	createfolder(domain)
	fresh_resolvers()

	# github(domain)
else:
	print("the domain is not valid.")
	exit()

if (validators.domain(domain)) and (gitflag!=""):
	github(domain)

if (validators.domain(domain)) and (subfinderflag!=""):
	subfinder(domain)

if (validators.domain(domain)) and (amassflag!=""):
	amass(domain)

if (validators.domain(domain)) and (shufflednsflag!=""):
	shuffledns(domain)

if (validators.domain(domain)) and (aquatoneflag!=""):
	aquatone(domain)

if (validators.domain(domain)) and (jswflag!=""):
	jswfind(domain)

if (validators.domain(domain)) and (ipflag!=""):
	asnlookup(domain)

