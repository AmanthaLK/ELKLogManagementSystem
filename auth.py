import os
import time as t
from tinydb import TinyDB, Query, where
from datetime import date, datetime, time
db = TinyDB('/opt/Filebeat_Logs/do_not_delete/db_ssh.json')



def insert(user,timeLogged,session,IPAddress):
    db.insert({'user':user,'timeLogged':timeLogged,'session':session,'IPAddress':IPAddress})

def getFieldData(fieldName,value,whereField):
    results = db.search(where(whereField) == value)
    result = [r[fieldName] for r in results]
    return result

def timeDiff(dt2, dt1):
    timedelta = dt2 - dt1
    seconds=timedelta.days * 24 * 3600 + timedelta.seconds
    seconds = seconds % (24 * 3600)
    hour = seconds // 3600
    seconds %= 3600
    minutes = seconds // 60
    seconds %= 60
    return "%d:%02d:%02d" % (hour, minutes, seconds)

file_name = '/var/log/auth.log'
seek_end = True
while True:  # handle moved/truncated files by allowing to reopen
    with open(file_name) as f:
        if seek_end:  # reopened files must not seek end
            f.seek(0, 2)
        while True:  # line reading loop
            line = f.readline()
            if not line:
                try:
                    if f.tell() > os.path.getsize(file_name):
                        # rotation occurred (copytruncate/create)
                        f.close()
                        seek_end = False
                        break
                except FileNotFoundError:
                    # rotation occurred but new file still not created
                    pass  # wait 1 second and retry
                t.sleep(1)

            if line != "":
                #print(line)

                if "Accepted password for" in line:
                    try:
                        IPAddress=line.split()[10]
                    except:
                        file_e = open("/opt/Filebeat_Logs/Exceptions.log", "a")
                        file_e.write(line)
                        file_e.close()
                
                elif "New session" in line:
                    try:
                        user = line.split()[10].replace(".","")
                        timeLogged = str(date.today().year) +" "+ line.split()[0] + " " + line.split()[1] +" "+line.split()[2]
                        session = line.split()[7]
                        insert(user,timeLogged,session,IPAddress)
                    except:
                        file_e = open("/opt/Filebeat_Logs/Exceptions.log", "a")
                        file_e.write(line)
                        file_e.close()

                elif "Failed password for invalid user" in line:
                    continue

                elif "message repeated 2 times: [ Failed password for" in line:
                    try:
                        time = line.split()[0] + " " + line.split()[1]+" "+line.split()[2]
                        user = line.split()[13]
                        IPAddress = line.split()[15]
                        data = time+" "+user+" "+IPAddress
                        file = open("/opt/Filebeat_Logs/SSHFail.log", "a")
                        file.write(data+"\n"+data+"\n")
                        file.close()

                    except:
                        file_e = open("/opt/Filebeat_Logs/Exceptions.log", "a")
                        file_e.write(line)
                        file_e.close()

                elif "Failed password for" in line:
                    try:
                        time = line.split()[0] + " " + line.split()[1]+" "+line.split()[2]
                        user = line.split()[8]
                        IPAddress = line.split()[10]
                        data = time+" "+user+" "+IPAddress
                        file = open("/opt/Filebeat_Logs/SSHFail.log", "a")
                        file.write(data+"\n")
                        file.close()
                    except:
                        file_e = open("/opt/Filebeat_Logs/Exceptions.log", "a")
                        file_e.write(line)
                        file_e.close()
                
                elif "Removed session" in line:
                    try:
                        session=session=line.split()[7].replace(".","")
                        user=getFieldData('user',session,'session')[0]
                        IPAddress=getFieldData('IPAddress',session,'session')[0]
                        timeLoggedIN=getFieldData('timeLogged',session,'session')[0]
                        timeLoggedOut=str(date.today().year) +" "+ line.split()[0] + " " + line.split()[1]+" "+line.split()[2]
                        
                        time1 = datetime.strptime(timeLoggedIN , '%Y %b %d %H:%M:%S')
                        time2 = datetime.strptime(timeLoggedOut , '%Y %b %d %H:%M:%S')
                        period = timeDiff(time2, time1)

                        timeLoggedIN = getFieldData('timeLogged',session,'session')[0].split()[1] +" "+ getFieldData('timeLogged',session,'session')[0].split()[2]+" "+getFieldData('timeLogged',session,'session')[0].split()[3]
                        timeLoggedOut = line.split()[0] + " " + line.split()[1]+" "+line.split()[2]
                        
                        data = timeLoggedOut+" "+timeLoggedIN+" "+user+" "+IPAddress+" "+period
                        
                        file = open("/opt/Filebeat_Logs/SessionPeriod.log", "a")
                        file.write(data+"\n")
                        file.close()

                        db.remove(where('session') == session)

                    except:
                        file_e = open("/opt/Filebeat_Logs/Exceptions.log", "a")
                        file_e.write(line)
                        file_e.close()
                
                else:
