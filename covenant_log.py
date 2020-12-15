#!/usr/bin/python3

import argparse # Parser for command-line options, arguments and sub-commands
import sqlite3 # Check SQLite database for changes in table
import sys # used sys to have clean exits of the program

YELLOW='\033[1;33m'
WHITE='\033[1;37m'
GREEN='\033[1;32m'
DARKGRAY='\033[1;30m'
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

            # Aligning text and numbers with .format() t.ly/upn8
            print("\n"+WHITE,"Operator's Tasks:",NOCOLOR)
            for row in all_rows:
                username, count = row
                print(LIGHTCYAN+"\t{:<20s}{:>1s}{:>6d}".format(username,":",count)+NOCOLOR)

            """ I guessed these by looking at covenant.db and Grunt.cs
                Uninitialized,  0
                Stage0,         1
                Stage1,         2
                Stage2,         3
                Active,         4
                Lost,           5
                Exited,         6
                Disconnected,   7
                Hidden          8
            """
            c.execute('select status, count(status) from grunts group by status;')
            all_rows = c.fetchall()
            print("\n"+WHITE,"Grunt Information:",NOCOLOR)
            for row in all_rows:
                grunt_status, grunt_count = row
                if grunt_status == 4: 
                    print(LIGHTCYAN+"\t{:<20s}{:>1s}{:>6d}".format("Grunts (Active)",":",grunt_count)+NOCOLOR)
                elif grunt_status == 5:
                    print(LIGHTCYAN+"\t{:<20s}{:>1s}{:>6d}".format("Grunts (Lost)",":",grunt_count)+NOCOLOR)
            print()
            #print(LIGHTCYAN,"  Grunts by hostname:\tToDo",NOCOLOR)
            #print(LIGHTCYAN,"  Grunts by username:\tToDo",NOCOLOR)
            #print(LIGHTCYAN,"  Grunts by integrity:\tToDo",NOCOLOR)
            
            #print(YELLOW,"\t\m/ (o_O) \m/",NOCOLOR,"\n")
        except sqlite3.error as e:
            print("database error: %s" % e)
        except exception as e:
            print("exception in _query: %s" % e)
        except attributeerror as e:
            print(e)
            print("unhandled exception in look function:", sys.exc_info()[0])
            exit()


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
                    print(GREEN+"[+] "+WHITE+operator+LIGHTCYAN,"command on",WHITE+hostname+LIGHTCYAN,"at",start_time,"completed at",end_time,NOCOLOR)
                    print(GREEN+"[+] "+LIGHTCYAN+command+NOCOLOR)
                    print(GREEN+"[+] "+LIGHTCYAN+"Results:\n"+YELLOW+output,NOCOLOR)
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
    parser.add_argument('-n', '--nocolor',default=None,action='store_true',help="remove color from output\n")
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-l','--log', default=None, action='store_true', help='Redteam operator formated logs.')
    group.add_argument('-o','--output', default=None, action='store_true', help='Results of Covenant Grunt Taskings input commands and resulting output.')

    if len(sys.argv)==1:
        print(LIGHTCYAN,banner,NOCOLOR)
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.db is not None:
        if options.nocolor is not None:
            YELLOW=GREEN=WHITE=LIGHTCYAN=NOCOLOR=''
        import os
        if os.stat(options.db).st_size == 0:
            print(YELLOW,"\nThe file: "+options.db+" is empty!\n",NOCOLOR)
        else:
            if options.log is not None or options.output is not None:
                get_logs(options.db)
            else:
                print_info(options.db)
        
    # exit program normally
    sys.exit(1)
