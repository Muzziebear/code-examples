# Python script to brute force discovery of target url directories and files using word list
# Resources used: "Black Hat Python" by Justin Seitz
# Interpreted using Python 3.5

import sys
import signal
import queue
import threading
import time
import urllib.request
import urllib.error
import urllib.parse


def signal_int_handler(signal, frame):
	print ("\nReceived interrupt.")
	sys.exit(0)


def build_wordlist(wordlist_file, resume):
	# read in the word list
	fd = open(wordlist_file,"r")
	raw_words = fd.readlines()
	fd.close()

	found_resume = False
	words = queue.Queue()

	for word in raw_words:
		word = word.rstrip()

		if resume is not None:
			if found_resume:
				words.put(word)
			elif word == resume:
				found_resume = True
				print ("Resuming wordlist from: %s" % (resume))
		else:
			words.put(word)

	return words


def dir_bruter(target_url, user_agent, word_queue, extensions=None):
	while not word_queue.empty():
		attempt_list = []
		attempt = word_queue.get()

		# check to see if there is a file extension, if not it's a directory path
		if "." not in attempt:
			attempt_list.append("/%s/" % attempt)

			# if bruteforcing extensions
			if extensions is not None:
				for ext in extensions:
					attempt_list.append("/%s%s"% (attempt, ext))
		else:
			attempt_list.append("/%s" % attempt)

		if len(attempt_list):
			# iterate over list of attempts 
			for brute in attempt_list:
				url = "%s%s" % (target_url, urllib.parse.quote(brute))
				#print ("Attempting %s" % (url))
				try:
					headers = {}
					headers["User-Agent"] = user_agent
					req = urllib.request.Request(url, headers=headers)

					response = urllib.request.urlopen(req)
					if len(response.read()):
						print ("[%d] => %s" % (response.code, url))

				except urllib.error.URLError as e:
					if hasattr(e, 'code') and e.code != 404:
						print ("!!! %d => %s" % (e.code, url))
					pass
		
		word_queue.task_done()


def main():
	thread_count = 50
	target_url = "http://testphp.vulnweb.com"
	user_agent = "Mozilla/5.0 (X11; Linux x86_64; rv:19.0) Gecko/20100101 Firefox/19.0"
	wordlist_file = "/home/user/SVNDigger/all.txt"  # from SVNDigger
	resume = None

	word_queue = build_wordlist(wordlist_file, resume)
	extensions = [".php", ".bak", ".orig", ".inc"]

	signal.signal(signal.SIGINT, signal_int_handler)
	
	try:
		for i in range(thread_count):
			t = threading.Thread(target=dir_bruter, args=(target_url, user_agent, word_queue, extensions,))
			t.daemon=True
			t.start()

		word_queue.join()

	except Exception as e:
		print(e)
		sys.exit(0)


if __name__ == '__main__':
	main()
