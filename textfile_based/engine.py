#!/usr/bin/python2
# Authors: Moses Arocha
# Brad Shumaker

#shell=true makes the program vulnerable to 'shell injection'. kinda cool, right?

import os
import pwd
import re
import socket
import subprocess
import sys
import subprocess as n
import pygame
import time

pygame.init()

reportLocation = './'
score = 0
#points = []


def readFile(file):
   if os.path.isfile(file):
      pro = subprocess.Popen("cat "+file, shell=True, stdout=subprocess.PIPE)
      display = pro.stdout.read()
      pro.stdout.close()
      pro.wait()
      return display
   else:
      errorWrite('File not found: '+file)

def errorWrite(msg):
   if os.path.isfile("Error_log.txt"):
      f = open("Error_log.txt", 'a')
      f.write(msg+'\n')
      f.close()
   else:
      f = open(reportLocation+'Error_log.txt', 'w+')
      f.write(msg+'\n')
      f.close()


def modScore(points): #changed to modScore, passing -1 will decrease
   global score
   score += points


def win_prompt(notifytxt):
   global score
   global reportLocation
   modScore(1) #will need to increase variables I pass to func later.
   pygame.mixer.music.load("a.mp3")
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
#######################################Engine_Code_Above
#####MODULES_BELOW

def schedule_cron(user, taskstring): #fix
   if os.path.isfile("/var/spool/cron/crontabs/"+user): #does the user have a cronjob?
      pro = subprocess.Popen("crontab -l -u"+user+" | grep \""+taskstring+"\"", shell=True, stdout=subprocess.PIPE)
      display = pro.stdout.read()
      pro.stdout.close()
      if not display:
         checkComplete("Removed Scheduled Task "+taskstring.capitalize())
   else:
      errorWrite('Error: '+user+' does not have a cron task. no points will be awarded')


def program_remove(program):
   pro = subprocess.Popen("dpkg -l | grep " +program, shell=True, stdout=subprocess.PIPE)
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
   pro = subprocess.Popen("uname -r", shell=True, stdout=subprocess.PIPE)
   display = pro.stdout.read()
   pro.stdout.close()
   display = display.split('.') #[0] = 4, [1]=4 [2]=0-genimg
   sysMinRev = display[2].split('-') #sysMinRev=0, cleans above last item
   if (display[0] >= kVersion):
      if (display[1] > kMajorRev) or (display[1] == kMajorRev and sysMinRev[0] > kMinRev):
         checkComplete('System Kernel Upgraded')

###
def user_passwd(user,hash):
   display = readFile('/etc/shadow')
   if user in display and hash not in display:
       checkComplete('Changed '+user+' Password')
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
           if group in line and user in line:
               checkComplete('Added '+user+' To The '+group+' Group')
       if 'remove' in change:
           if group in line and user not in line:
               checkComplete('Removed '+user+' From the '+group+' Group')


def firewall_check(): #changed from crontab -e, was this a different check?
   pro = subprocess.Popen("ufw status", shell=True, stdout=subprocess.PIPE)
   display = pro.stdout.read()
   pro.stdout.close()
   pro.wait()
   if 'inactive' not in display:
      checkComplete('Enabled The Firewall')

#hey this is works on multiple versions of linux ;-)
def firewall_rule(status,port): #Status is: ACCEPT or DROP
   pro = subprocess.Popen("iptables -L -n | grep  \":"+port+"$\" | grep "+status.upper(), shell=True, stdout=subprocess.PIPE)
   display = pro.stdout.read() #search for port with nothing after it. IE: 22 not 2200 will trigger points
   pro.stdout.close()
   pro.wait()
   if display:
      checkComplete('Firewall Rule '+status+'ing port '+port)

def console_reboot(): #Per Debian Security Guide. Go ahead...read it.
   if os.path.isfile("/etc/init/control-alt-delete.conf"):
      pro = subprocess.Popen("cat /etc/init/control-alt-delete.conf | grep shutdown | grep -v ^#", shell=True, stdout=subprocess.PIPE)
      display = pro.stdout.read()
      pro.wait()
      #display.startswith('#')
      #for line in display.split('\n')
         #if 'shutdown' in line and line.startswith('#')
            #completeCheck('')
      if not display:
         completeCheck('Prevented Ctrl+Alt+Del Reboot')
   else: #they deleted the file, give points
      completeCheck('Prevented Ctrl+Alt+Del Reboot')


def console_userlist():
   if os.path.isfile("/etc/lightdm/lightdm.conf"):
      pro = subprocess.Popen("cat /etc/lightdm/lightdm.conf", shell=True, stdout=subprocess.PIPE)
      display=pro.stdout.read()
      pro.wait()
      if 'greeter-hide-users = true' in display and 'greeter-show-manual-login = true' in display:
         checkComplete('User List Hidden At Login')


def password_complexity(): #break these into different settings or lump them into one...
   pro = subprocess.Popen("cat /etc/pam.d/common-password", shell=True, stdout=subprocess.PIPE)
   display=pro.stdout.read()
   pro.wait()
   if "remember=5" in display:
     checkComplete('Added Password History')
   if "minlen=8" in display:
     checkComplete('Enforced Password Length')
   if "ucredit" and "lcredit" and "dcredit" and "ocredit" in display:
     checkComplete('Added Password Complexity')


def password_history():
   pro = subprocess.Popen("cat /etc/login.defs", shell=True, stdout=subprocess.PIPE)
   display = pro.stdout.read()
   pro.wait()
   if "PASS_MAX_DAYS " and "PASS_MIN_DAYS " and "PASS_WARN_AGE " in display:
     checkComplete('Added Password History Standards')


def account_policy():
   pro = subprocess.Popen("cat /etc/pam.d/common-auth", shell=True, stdout=subprocess.PIPE)
   display = pro.stdout.read()
   pro.wait()
   if "deny=" and "unlock_time=" in display:
      checkComplete('Set Account Policy Standards')


def malware_check(name, file_path):
   if not os.path.isfile(file_path):
      checkComplete('Removed Harmful File: '+name)


#critical Services listed below
def apache_security(file):
   if os.path.isfile(file):
      pro = subprocess.Popen("cat " +file, shell=True, stdout=subprocess.PIPE)
      display = pro.stdout.read()
      pro.wait()
      if "ServerSignature" and "ServerTokens" in display:
          checkComplete('Secured Apache Web Server')


def ssh_security():
   if os.path.isfile('/etc/ssh/sshd_config'):
      pro = subprocess.Popen("cat /etc/ssh/sshd_config", shell=True, stdout=subprocess.PIPE)
      display = pro.stdout.read()
      pro.wait()
      if "PermitRootLogin no" in display:
         checkComplete('Disabled Root Login for SSH')
      #subpro = subprocess.Popen("cat /etc/ssh/sshd_config", shell=True, stdout=subprocess.PIPE)
      #subdisplay = subpro.stdout.read()
      #subpro.wait()
      if "AllowUsers" in subdisplay:
         checkComplete('Secured SSH User Login')


def samba_security():
   if os.path.isfile('/etc/samba/smb.conf'): #make sure samba is installed
      pro = subprocess.Popen("cat /etc/samba/smb.conf", shell=True, stdout=subprocess.PIPE)
      display = pro.stdout.read()
      pro.wait()
      if "guest ok = no" in display:
         checkComplete('Samba Server Guest Disabled')


def php_security():
   if os.path.isfile('/etc/php/7.0/apache2/php.ini'): #make sure php7 is installed
      pro = subprocess.Popen("cat /etc/php/7.0/apache2/php.ini | grep expose_php", shell=True, stdout=subprocess.PIPE)
      display = pro.stdout.read()
      pro.wait()
      if "Off" in display:
        checkComplete('secured PHP Version')


def waf_check():
   if os.path.isfile("/etc/modsecurity/modsecurity.conf-recommended"):
       pro = subprocess.Popen("cat /etc/modsecurity/modsecurity.conf-recommended", shell=True, stdout=subprocess.PIPE)
       display = pro.stdout.read()
       pro.stdout.close()
       pro.wait()
       if "SecRequestBodyAccess Off" in display:
           checkComplete('Added WAF Protection to APache Server')


#End of critical services


def main():
   global score
   global points


   schedule_cron('bobZaggit','ping') #user & search string
   firewall_rule('drop','80') #action(drop|accept,port#)
   firewall_rule('accept','22')
   console_userlist() #Don't display users @ login
   console_reboot() #prevent Ctrl+Alt+del
   program_autoupdates() #Check for unattended-upgrades
   program_remove('nmap')
   program_remove('medusa')
   program_kernel('4','8','0') 	#Ubuntu16 ships with 4.4.0, btw.
   user_check('remove','baduser1')
   user_check('add','cpstudent')
   user_hiddenroot()
   group_check('remove','User1','sudo') 	#add|remove user from group
   group_check('add','cpstudent','adm')
   user_passwd('cyber', '$6$FicC')
   user_passwd('jimmy', '$6$QMoj')
   user_passwd('ben',   '$6$SkT')
   malware_check('.virus.py', '/home/notauser/.virus.py')
   malware_check('setup.py', '/root/Firewall/setup.py')
   firewall_check() #is this thing on?
   program_respos('Security','http://security.ubuntu.com/ubuntu')
   password_complexity()
   password_history()
   account_policy()
   user_guest()
   #apache_security('/etc/apache2/conf-available/myconf.conf')
   #ssh_security()
   #php_security()
   #waf_check()
   #samba_security()

   #for point in points: #Write this to the html file and have inline updated
   #    print point
   print str(score),"/25 Total Points"


if __name__ == '__main__':
 main()
