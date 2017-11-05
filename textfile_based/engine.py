#!/usr/bin/python2
# Author is Moses Arocha
# Contributions: Brad Shumaker

#added win_prompt() to both alert and write to file
#removed all instances of f.open etc
# score = score +1 changed to score += 1. it's good to be lazy.
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

#pygame.init()
#pygame.mixer.music.load("a.mp3")
reportLocation = './'
score = 0
#points = []

def modScore(points): #changed to modScore, passing -1 will decrease
   global score
   score += points


def win_prompt(notifytxt):
   global score
   global reportLocation
   modScore(1) #will need to increase variables I pass to func later.
   n.call(['notify-send', 'Points Awarded!', notifytxt])
   pygame.init()
   pygame.mixer.music.load("a.mp3")
   pygame.mixer.music.play()
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


def program_remove(program):
   pro = subprocess.Popen("dpkg -l | grep " +program, shell=True, stdout=subprocess.PIPE)
   display = pro.stdout.read()
   pro.stdout.close()
   pro.wait()
   if not display:
      checkComplete('Program '+program+' removed')


def program_respos(topic,respository):
   pro = subprocess.Popen("cat /etc/apt/sources.list", shell=True, stdout=subprocess.PIPE)
   display = pro.stdout.read()
   pro.stdout.close()
   pro.wait()
   if respository in display:
      checkComplete('Respository '+topic+' Added To Debian Package Lists')


def program_kernel(kVersion, kMajorRev, kMinRev): #Pass the minimum kernel version to get points
   pro = subprocess.Popen("uname -r | cut -d- -f1", shell=True, stdout=subprocess.PIPE)
   display = pro.stdout.read()
   pro.stdout.close()
   if (display[0] >= kVersion):
      if (display[2] > kMajorRev) or (display[2] == kMajorRev and display[4:] > kMinRev): 
         checkComplete('System Kernel Upgraded')


def user_passwd(user,hash):
   pro = subprocess.Popen("cat /etc/shadow | grep "+user, shell=True, stdout=subprocess.PIPE)
   display = pro.stdout.read()
   pro.stdout.close()
   pro.wait()
   if user in display: #no points for deleting valid users!
      if hash not in display:
         checkComplete('Changed '+user+' Password')
   #else:
      #remove points, coming soon...


def user_hiddenroot():
   pro = subprocess.Popen("cat /etc/passwd | grep -v root | grep :0:0:", shell=True, stdout=subprocess.PIPE)
   display = pro.stdout.read()
   pro.wait()
   if not display:
      checkComplete('Hidden Root User Removed')


def user_remove(badUser): #renamed _remove because it checks removal not existance. 
   pro = subprocess.Popen("cat /etc/pam.d/common-auth", shell=True, stdout=subprocess.PIPE)
   display = pro.stdout.read()
   pro.wait()
   if not badUser in display:
      checkComplete('Removed The User '+badUser)


def user_guest(file_path):
   if os.path.isfile(file_path):
     pro = subprocess.Popen("cat "+file_path, shell=True, stdout=subprocess.PIPE)
     display = pro.stdout.read()
     pro.wait()
     if "allow-guest=false" in display:
        checkComplete('Disabled Guest Account')


def group_check(change,user,group): #change: 0 - Remove, 1 - add. Example: group_check(1, baduser, sudo)
   pro = subprocess.Popen("cat /etc/group | grep \""+group+"\"", shell=True, stdout=subprocess.PIPE)
   display = pro.stdout.read()
   pro.wait()
   if change and (user in display):
      checkComplete('Added '+user+' To The '+group+' Group')
   if not change and (user not in display):
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

   firewall_rule('drop','80')
   firewall_rule('accept','22')
   console_userlist()
   console_reboot()
   program_remove('nmap')
   program_remove('medusa')
   program_kernel('4','8','0')
   user_remove('jennylewis')
   user_remove('moses')
   user_hiddenroot()
   group_check('1','juan','sudo')
   user_passwd('cyber', '$6$FicC')
   user_passwd('jimmy', '$6$QMoj')
   user_passwd('ben',   '$6$SkT') 
   malware_check('.virus.py', '/home/cyber/.virus.py')
   malware_check('setup.py', '/root/Firewall/setup.py')
   firewall_check()
   program_respos('General','http://us.archive.ubuntu.com/ubuntu')
   program_respos('Security','http://security.ubuntu.com/ubuntu')
   password_complexity()
   password_history()
   account_policy()
   user_guest('/etc/lightdm/lightdm.conf')
   apache_security('/etc/apache2/conf-available/myconf.conf')
   #ssh_security()
   #php_security()
   #waf_check()
   #samba_security()

   #for point in points: #Write this to the html file and have inline updated
   #    print point
   print str(score),"/25 Total Points"


if __name__ == '__main__':
 main()

