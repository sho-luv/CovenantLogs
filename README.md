# CovenantLogs

<h4 align="center">Covenant Database Parsing Tool</h4>
<p align="center">
  <a href="https://twitter.com/sho_luv">
  <img src="https://img.shields.io/badge/Twitter-%40sho_luv-blue.svg">
  </a>
</p>

# covenant_log.py

Python3 Tool to parse Covenant.db to extract information to be used in Red Team Operator Logs.
It can also extract all Grunt commands and resulting output. This can be useful for searching 
and sorting data with linux tools such as grep, awk, etc.


## Usage of covenant_log.py
```
                  888         888
                  888         888
                  888         888
 .d88b.  88888b.  888888      888  .d88b.   .d88b.  .d8888b
d88""88b 888 "88b 888         888 d88""88b d88P"88b 88K
888  888 888  888 888         888 888  888 888  888 "Y8888b.
Y88..88P 888 d88P Y88b.       888 Y88..88P Y88b 888      X88
 "Y88P"  88888P"   "Y888      888  "Y88P"   "Y88888  88888P'
         888                                    888
         888                               Y8b d88P
         888                                "Y88P"
     
usage: covenant_log.py [-h] [-l | -o] covenant.db

This program pareses covenant.db to output opt logs in R7 Format

positional arguments:
  covenant.db   Covenant database

optional arguments:
  -h, --help    show this help message and exit
  -l, --log     Redteam operator formated logs.
  -o, --output  Results of Covenant commands all of them.
```
