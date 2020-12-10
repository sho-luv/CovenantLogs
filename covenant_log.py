#!/usr/bin/python3

import argparse # Parser for command-line options, arguments and sub-commands
import sqlite3 # Check SQLite database for changes in table
import sys # used sys to have clean exits of the program

YELLOW='\033[1;33m'
WHITE='\033[1;37m'
LIGHTCYAN='\033[1;36m'
NOCOLOR='\033[0m'

############################################################
# Written by: Leon Johnson (sho_luv)
# Website: https://www.sholuv.net
# Twitter: @sho_luv
# Covenant C2: https://github.com/cobbr/Covenant
#
# This program simply pares the Covenant database
# to pull out information used in Red Team operators' log
# 

def print_info(sqlfile):
    if sqlfile is not None:
        try:
            conn = sqlite3.connect(sqlfile)
            c = conn.cursor()
            c.execute('SELECT '\
                'AspNetUsers.UserName,'\
                'count(AspNetUsers.UserName) '\
                'FROM GruntCommands '\
                'INNER JOIN AspNetUsers ON (GruntCommands.UserId = AspNetUsers.Id) '\
                'GROUP BY AspNetUsers.UserName;')

            all_rows = c.fetchall()
        except sqlite3.error as e:
            print("database error: %s" % e)
        except exception as e:
            print("exception in _query: %s" % e)
        except attributeerror as e:
            print(e)
            print("unhandled exception in look function:", sys.exc_info()[0])
            exit()

        print("\n"+WHITE,"Operator's Tasks:",NOCOLOR)
        for row in all_rows:
            username, count = row
            print(LIGHTCYAN,"  ",username,":\t",count,NOCOLOR)

        print("\n"+WHITE,"Grunt Information:",NOCOLOR)
        print(LIGHTCYAN,"  Grunts by hostname:\tToDo",NOCOLOR)
        print(LIGHTCYAN,"  Grunts by username:\tToDo",NOCOLOR)
        print(LIGHTCYAN,"  Grunts by integrity:\tToDo",NOCOLOR)
        
        print("\n"+YELLOW,"    \m/ (o_O) \m/",NOCOLOR,"\n")


def get_logs(sqlfile):
    if sqlfile is not None:
        try:
            # note: if there are "Database error: unable to open database file"
            # errors this is due to the sqlite database being locked by another
            # process. By default connections will wait 5 seconds befor timeouts
            # with database locked errors. To avoid this we can increse the
            # timeout from the default of 5 seconds = 5000 to something like 
            # 10 seconds or 10000 to avoid thees database locked errors
            conn = sqlite3.connect(sqlfile)
            c = conn.cursor()
            c.execute('SELECT '\
                'STRFTIME("%Y-%m-%d %H:%M:%S", GruntTaskings.TaskingTime), '\
                'STRFTIME("%Y-%m-%d %H:%M:%S", GruntTaskings.CompletionTime), '\
                'GruntCommands.Command, '\
                'CommandOutputs.Output, '\
                'Grunts.Hostname, '\
                'Listeners.Urls, '\
                'AspNetUsers.UserName,'\
                'STRFTIME("%Y-%m-%d %H:%M:%S",GruntTaskings.CompletionTime)'\
                'FROM GruntCommands '\
                'INNER JOIN GruntTaskings ON (GruntCommands.Id = GruntTaskings.GruntCommandId)'\
                'INNER JOIN Grunts ON (GruntCommands.gruntId = Grunts.Id)'\
                'INNER JOIN CommandOutputs ON (GruntCommands.Id = CommandOutputs.Id)'\
                'INNER JOIN Listeners ON (Grunts.listenerId = Listeners.Id)'\
                'INNER JOIN AspNetUsers ON (GruntCommands.UserId = AspNetUsers.Id);')

            all_rows = c.fetchall()
            for row in all_rows:
                start_time, end_time, command, output, hostname, destination, operator, log_time = row
                destination = destination.replace('"', '').replace('[','').replace(']','')
                if options.output is True:
                    print(LIGHTCYAN+"Command: ",command,NOCOLOR)
                    print(YELLOW+"Results: ", output,NOCOLOR)
                elif options.log is True:
                    print(start_time+",",end_time+",",command+",,,,",hostname+",",destination+",,",operator+",",log_time)

        except sqlite3.error as e:
            print("database error: %s" % e)
        except exception as e:
            print("exception in _query: %s" % e)
        except attributeerror as e:
            print(e)
            print("unhandled exception in look function:", sys.exc_info()[0])
            exit()


if __name__ == "__main__":
    # executes only if run as a script

    banner = """
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
    """
    
    parser = argparse.ArgumentParser(description='This program pareses covenant.db to output opt logs in R7 Format')
    parser.add_argument('db', action='store', metavar='covenant.db', help="Covenant database\n")
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-l','--log', default=None, action='store_true', help='Redteam operator formated logs.')
    group.add_argument('-o','--output', default=None, action='store_true', help='Results of Covenant commands all of them.')

    if len(sys.argv)==1:
        print(LIGHTCYAN,banner,NOCOLOR)
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.db is not None:
        if options.log is not None or options.output is not None:
            get_logs(options.db)
        else:
            print_info(options.db)
        
    # exit program normally
    sys.exit(1)
