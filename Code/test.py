import datetime
from crontab import CronTab

my_crons = CronTab(user='te')
for job in my_crons:
    print ("Frequencty: " + str(job.frequency_per_hour()))
    sch = job.schedule(date_from=datetime.datetime.now())
    print (sch.get_next())