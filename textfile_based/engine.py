#!/usr/bin/python2
# Authors: Moses Arocha
# Brad Shumaker

#shell=true makes the program vulnerable to 'shell injection'. kinda cool, right?

import os
import platform
import pwd
import re
import socket
import subprocess
import sys
import subprocess as n
import pygame
import datetime
import ConfigParser

pygame.init()

reportLocation = '/home/cpstudent/Desktop/'
score = 0
#points = []


def readFile(file):
   if os.path.isfile(file):
      with open (file,"r") as fileload:
         inspectData = fileload.read()
      return inspectData
   else:
      errorWrite('File not found: '+file)

def errorWrite(msg):
   timeStamp = datetime.datetime.now()
   if os.path.isfile("Error_log.txt"):
      f = open("Error_log.txt", 'a')
      f.write(str(timeStamp)+','+msg+'\n')
      f.close()
   else:
      f = open(reportLocation+'Error_log.txt', 'w+')
      f.write(str(timeStamp)+','+msg+'\n')
      f.close()


def modScore(points): #changed to modScore, passing -1 will decrease
   global score
   score += points


def win_prompt(notifytxt):
   global reportLocation
   modScore(1) #will need to increase variables I pass to func later.
   pygame.mixer.music.load("/ScoringEngine/a.mp3")
   pygame.mixer.music.play()
   n.call(['notify-send', 'Points Awarded!', notifytxt])
   f = open(reportLocation+'Score_Report.html','a')
   f.write('&bull;' +notifytxt+'<br>\n')
   f.close()


def checkComplete(notifytxt): #Prevent Duplicate Prompts
   global reportLocation
   #does the .html exist? Need more of these to prevent error messages.
   if os.path.isfile(reportLocation+"Score_Report.html"):
       pro = subprocess.Popen("grep \"" +notifytxt+ "\" "+reportLocation+"Score_Report.html", shell=True, stdout=subprocess.PIPE)
       display = pro.stdout.read()
       pro.stdout.close()
       pro.wait()
       if not display:
         win_prompt(notifytxt)
       else:
         modScore(1) #without this the end console provides an invaled #/total completed
   #if the file doesn't exist then they haven't completed. GIVE THEM CAKE!
   else:
      f = open(reportLocation+'Score_Report.html', 'w+')
      win_prompt(notifytxt)
#######################################Engine_Code_Above###############################################################


#######################################MODULES_BELOW###################################################################

#search file for the line ANSWER <strong> and award points.
#name should be something like: ForensicsQuestion1
def forensic_question(number,file,string):
    display = readFile(file)
    for line in display.split('\n'):
      if 'ANSWER' in line:
        if string in line:
          checkComplete("Forensic Question"+str(number)+" Correct")

def schedule_cron(user, taskstring): #fix
   if os.path.isfile("/var/spool/cron/crontabs/"+user): #does the user have a cronjob?
      pro = subprocess.Popen("/usr/bin/crontab -l -u"+user+" | grep \""+taskstring+"\" | grep -v ^#", shell=True, stdout=subprocess.PIPE)
      display = pro.stdout.read()
      pro.stdout.close()
      if not display:
         checkComplete("Removed Scheduled Task "+taskstring.capitalize())
   else:
      errorWrite('Error: '+user+' does not have a cron task. no points will be awarded')


def program_remove(program):
   pro = subprocess.Popen("/usr/bin/dpkg -l | grep " +program, shell=True, stdout=subprocess.PIPE)
   display = pro.stdout.read()
   pro.stdout.close()
   pro.wait()
   if not display:
      checkComplete('Program '+program+' removed')

###
def program_respos(topic,respository):
   display = readFile("/etc/apt/sources.list")
   if respository in display:
      checkComplete('Respository '+topic+' Added To Debian Package Lists')
###
def program_autoupdates():
   display = readFile("/etc/apt/apt.conf.d/20auto-upgrades")
   if 'Unattended-Upgrade "1"' in display and 'Update-Package-Lists "1"' in display:
      checkComplete('Automatic Updates Applied')

###?
def program_kernel(kVersion, kMajorRev, kMinRev): #Pass the minimum kernel version to get points
   pro = subprocess.Popen("/bin/uname -r", shell=True, stdout=subprocess.PIPE)
   display = pro.stdout.read()
   pro.stdout.close()
   display = display.split('.') #[0] = 4, [1]=4 [2]=0-genimg
   sysMinRev = display[2].split('-') #sysMinRev=0, cleans above last item
   if (int(display[0]) >= int(kVersion)):
      if (int(display[1]) > int(kMajorRev)) or (int(display[1]) == int(kMajorRev) and int(sysMinRev[0]) > int(kMinRev)):
         checkComplete('System Kernel Upgraded')

###
def user_passwd(user,hash):
   display = readFile('/etc/shadow')
   for line in display.split('\n'):
      if user in line and hash not in line:
            checkComplete('Changed '+user+'\'s Password')
   #else:
      #remove points, coming soon...

###
def user_hiddenroot(): #change: add or remove. Example: group_check('remove', 'baduser', 'sudo')
   display = readFile('/etc/passwd')
   for line in display.split('\n'):
       if ':0:0:' in line and 'root' not in line:
           return 0
   else:
      checkComplete('Removed Hidden Root Account')

###
def user_check(action, user): #user_check(add|remove,<username>)
   display = readFile('/etc/passwd')
   if 'add' in action and user in display:
       checkComplete('Added The User '+user)
   if 'remove' in action and not user in display:
       checkComplete('Removed The User '+user)

###
def user_guest():
   display = readFile('/etc/lightdm/lightdm.conf')
   if display and "allow-guest=false" in display:
      checkComplete('Disabled Guest Account')

###
def group_check(change,user,group): #change: add or remove. Example: group_check('remove', 'baduser', 'sudo')
   display = readFile('/etc/group')
   for line in display.split('\n'):
       if 'add' in change:
           if group+':' in line and user in line:#added: to varibale to prevent false pos
               checkComplete('Added '+user+' To The '+group+' Group')
       if 'remove' in change:
           if group+':' in line and user not in line: #added : to group to prevent false pos
               checkComplete('Removed '+user+' From the '+group+' Group')


def firewall_check(): #changed from crontab -e, was this a different check?
   pro = subprocess.Popen("/usr/sbin/ufw status", shell=True, stdout=subprocess.PIPE)
   display = pro.stdout.read()
   pro.stdout.close()
   pro.wait()
   if 'inactive' not in display:
      checkComplete('Enabled The Firewall')

#hey this is works on multiple versions of linux ;-)
def firewall_rule(status,port): #Status is: ACCEPT or DROP
   pro = subprocess.Popen("/sbin/iptables -L -n | grep  \":"+port+"$\" | grep "+status.upper(), shell=True, stdout=subprocess.PIPE)
   display = pro.stdout.read() #search for port with nothing after it. IE: 22 not 2200 will trigger points
   pro.stdout.close()
   pro.wait()
   if display:
      checkComplete('Firewall Rule '+status+'ing port '+port)
###
def console_reboot(): #Per Debian Security Guide. Go ahead...read it.
   if os.path.isfile("/etc/init/control-alt-delete.conf"):
      display = readFile("/etc/init/control-alt-delete.conf")
      for line in display.split('\n'):
         if 'shutdown' in line and line.startswith('#'):
            checkComplete('Prevented Ctrl+Alt+Del Reboot')
   else: #they deleted the file, give points
      checkComplete('Prevented Ctrl+Alt+Del Reboot')

###
def console_userlist():
   if os.path.isfile("/etc/lightdm/lightdm.conf"):
      display = readFile("cat /etc/lightdm/lightdm.conf")
      if 'greeter-hide-users' in display and 'greeter-show-manual-login' in display:
         checkComplete('User List Hidden At Login')


def password_complexity(): #break these into different settings or lump them into one...
   pro = subprocess.Popen("cat /etc/pam.d/common-password", shell=True, stdout=subprocess.PIPE)
   display=pro.stdout.read()
   pro.wait()
   if "remember=" in display:
     checkComplete('Added Password History')
   if "minlen=" in display:
     checkComplete('Enforced Password Length')
   if "ucredit" and "lcredit" and "dcredit" and "ocredit" in display:
     checkComplete('Added Password Complexity')

###
def password_history():#FIX
   display = readFile("/etc/login.defs")
   if "PASS_MAX_DAYS " and "PASS_MIN_DAYS " and "PASS_WARN_AGE " in display:
     checkComplete('Added Password History Standards')

###
def account_policy():
   display = readFile("/etc/pam.d/common-auth")
   if "deny=" and "unlock_time=" in display:
      checkComplete('Set Account Policy Standards')


def badfile_check(type, name, file_path):
   if not os.path.isfile(file_path+name):
      checkComplete('Removed '+type+' File: '+name)


#critical Services listed below
def apache_security(file):
   allsettings = 0
   if os.path.isfile(file):
      display = readFile(file)
      for line in display.split('\n'):
         if "serversignature off" in line.lower() and not line.startswith('#'):
	    allsettings += 1
	 if "servertokens prod" in line.lower() and not line.startswith('#'):
	    allsettings += 1
      if allsettings == 2:
	 checkComplete('Secured Apache Web Server')


def ssh_security():
   if os.path.isfile('/etc/ssh/sshd_config'):
      display = readFile("/etc/ssh/sshd_config")
      if "PermitRootLogin no" in display:
         checkComplete('Disabled Root Login for SSH')
      if "AllowUsers" in display:
        checkComplete('Secured SSH User Login')


def samba_security():
   if os.path.isfile('/etc/samba/smb.conf'): #make sure samba is installed
      display = readFile("/etc/samba/smb.conf")
      if "guest ok = no" in display:
         checkComplete('Samba Server Guest Disabled')


def php_security():
   if os.path.isfile('/etc/php/7.0/apache2/php.ini'): #make sure php7 is installed
      display = readFile("/etc/php/7.0/apache2/php.ini")
      if "expose_php = off" in display:
        checkComplete('secured PHP Version')


def waf_check():
   if os.path.isfile("/etc/modsecurity/modsecurity.conf"):
       display = readFile("/etc/modsecurity/modsecurity.conf")
       if "SecRuleEngine On" in display:
           checkComplete('Web Application Firewall Enabled')
#####WORDPRESS CHECKS
def crit_wordpress_upate(version):
    if os.path.isfile("/var/www/html/wp-includes/version.php"):
        display = readFile("/var/www/html/wp-includes/version.php").split('\n')
        for line in display:
            if 'wp_version = ' in line and version in line:
               checkComplete('Wordpress Upgraded')

def crit_wordpress_plugin(name,version):
    version = version.split('.')
    if os.path.isfile("/var/www/html/wp-content/plugins/"+name+"/"+name+".php"):
        display = readFile("/var/www/html/wp-content/plugins/"+name+"/"+name+".php").split('\n')
        for line in display:
            if 'version:' in line.lower():
               currentver = line.split(':')
               currentver = currentver[1].split('.')
               if int(currentver[0]) >= int(version[0]) and int(currentver[1]) >= int(version[1]):
                   checkComplete('Wordpress Plugin '+name.title()+' Upgraded')

def crit_wordpress_theme(name,version):
    version = version.split('.')
    if os.path.isfile("/var/www/html/wp-content/themes/"+name+"/style.css"):
        display = readFile("/var/www/html/wp-content/themes/"+name+"/style.css").split('\n')
        for line in display:
            if 'version:' in line.lower():
               currentver = line.split(':')
               currentver = currentver[1].split('.')
               if int(currentver[0]) >= int(version[0]) and int(currentver[1]) >= int(version[1]):
                   checkComplete('Wordpress Theme '+name.title()+' Upgraded')
#End of critical services


def main():
   global score
   global points

   config = ConfigParser.ConfigParser(allow_no_value=True)
   config.read('/ScoringEngine/engine.conf')

#find the remove options in engine.conf
   if config.options('FORENSICS'):
    forensicnum = 1
    for answer in config.options('FORENSICS'):
        questionLocation = reportLocation+'Forensic_Question'+str(forensicnum)+'.txt' #/home/cpstudent/Desktop/Forensic_Question1.txt
    forensic_question(forensicnum,questionLocation,config.get('FORENSICS',answer))
    forensicnum +=1

   if config.options('PROGRAM'):
       if 'remove' in config.options('PROGRAM'):
          for prog in config.get('PROGRAM','REMOVE').split(','):
             program_remove(prog)
         #addone to total
       if 'kernel' in config.options('PROGRAM'):
           KernelVer = config.get('PROGRAM','KERNEL').split('.')
           program_kernel(KernelVer[0],KernelVer[1],KernelVer[2]) 	#Ubuntu16 ships with 4.4.0, Ubuntu 14: 3.19
           #addone to total
       if 'autoupdates' in config.options('PROGRAM'):
          program_autoupdates()
          #addone to total
       if 'respos' in config.options('PROGRAM'): ##FIXME loophere
          resposdata = config.get('PROGRAM','RESPOS').split(',')
          program_respos(resposdata[0],resposdata[1])
   if config.options('CRONTASK'):
      for user in config.options('CRONTASK'):
         schedule_cron(user,config.get('CRONTASK',user))
      #addone to Total

   if config.options('FIREWALL'):
      for fwchk in config.options('FIREWALL'):
         if 'firewallstatus' in fwchk:
            firewall_check()
            #addone to total
         if 'acceptrule' in fwchk:
            for port in config.get('FIREWALL','ACCEPTRULE').split(','):
               firewall_rule('accept',port)
              #addone to total
         if 'droprule' in fwchk:
            for port in config.get('FIREWALL','DROPRULE').split(','):
               firewall_rule('drop',port)
             #addone to total

   if config.options('CONSOLE'):
       if 'disablectrlaltdel' in config.options('CONSOLE'):
          console_reboot()
       if 'hideuserslogin' in config.options('CONSOLE'):
          console_userlist

   if config.options('GROUPS'):
      for group in config.options('GROUPS'):
          if 'groupadd' in group:
              setting = config.get('GROUPS',group).split(',')
              group_check('add',setting[0],setting[1])
          if 'groupremove' in group:
              setting = config.get('GROUPS',group).split(',')
              group_check('remove',setting[0],setting[1])

   if config.options('USERSETTINGS'):
       for option in config.options('USERSETTINGS'):
           if 'hiddenroot' in config.options('USERSETTINGS'):
               user_hiddenroot()
           if 'disableguest' in config.options('USERSETTINGS'):
               user_guest()

   if config.options('PASSWORDCHANGE'):
      for change in config.options('PASSWORDCHANGE'):
         setting = config.get('PASSWORDCHANGE',change).split(',')
         user_passwd(setting[0],setting[1])

   if config.options('PASSWORDPOLICY'):
      if 'policy' in config.options('PASSWORDPOLICY'):
         account_policy()
      if 'history' in config.options('PASSWORDPOLICY'):
         account_policy()
      if 'complexity' in config.options('PASSWORDPOLICY'):
         password_complexity()

   if config.options('BADFILE'):
       for baditems in config.options('BADFILE'):
           badfile = config.get('BADFILE',baditems).split(',')
           badfile_check(badfile[0],badfile[1],badfile[2])

   if config.options('ADDUSERS'):
       for users in config.options('ADDUSERS'):
           user_check('add',users)

   if config.options('REMOVEUSERS'):
      for remove in config.options('REMOVEUSERS'):
         user_check('remove',remove)

   if config.options('CRITSERVICE'):
      for service in config.options('CRITSERVICE'):
          if 'php' in service:
              php_security()
          if 'apache' in service:
		    apache_security('/etc/apache2/conf-enabled/security.conf')
  	   	    waf_check()
          if 'ssh' in service:
              ssh_security()
          if 'samba' in service:
              samba_security()

   if config.options('WORDPRESS'):
      for option in config.options('WORDPRESS'):
              if 'theme' in option:
                  themever = config.get("WORDPRESS",option).split(',')
                  crit_wordpress_theme(themever[0],themever[1])
              if 'plugin' in option:
                  plugsetting = config.get("WORDPRESS",option).split(',')
                  crit_wordpress_plugin(plugsetting[0],plugsetting[1])
      if 'update' in config.options('WORDPRESS'):
          crit_wordpress_upate(config.get('WORDPRESS','update'))



   #for point in points: #Write this to the html file and have inline updated
   #    print point
   print str(score),"/25 Total Points"


if __name__ == '__main__':
 main()
