#!/usr/bin/python2
# Author is Moses Arocha
# Contributions: Brad Shumaker

#changes 11/2/17
#added prompt() to both alert and write to file
#removed all instances of f.open etc
# score = score +1 changed to score += 1. it's good to be lazy.

import os
import pwd
import re
import socket
import subprocess
import sys

#!/usr/bin/python2

import subprocess as n
import pygame
import time

pygame.init()
pygame.mixer.music.load("/score/a.mp3")

score = 0
points = []

def prompt(notifytxt):
   n.call(['notify-send', 'Points Awarded', notifytxt])
   pygame.mixer.music.play()
   f = open('index.html','a')
   f.write(notifytxt+'<br>')
   f.close()

def program_remove(program):
   global score
   pro = subprocess.Popen("dpkg -l | grep " +program, shell=True, stdout=subprocess.PIPE)
   display = pro.stdout.read()
   pro.stdout.close()
   pro.wait()
   if not display:
      score += 1
      prompt('Removed The Tool '+program)



def waf_check():
   global score
   if os.path.isfile("/etc/modsecurity/modsecurity.conf-recommended"):
       pro = subprocess.Popen("cat /etc/modsecurity/modsecurity.conf-recommended", shell=True, stdout=subprocess.PIPE)
       display = pro.stdout.read()
       pro.stdout.close()
       pro.wait()
       if "SecRequestBodyAccess Off" in display:
           score = score+1
           prompt('Added WAF Protection to APache Server')


def update_programs(topic,respository):
   global score
   pro = subprocess.Popen("cat /etc/apt/sources.list", shell=True, stdout=subprocess.PIPE)
   display = pro.stdout.read()
   pro.stdout.close()
   pro.wait()
   if respository in display:
      score = score+1
      prompt('Respository Added To Debian Package Lists')


def user_passwd(user,hash):
   global score
   pro = subprocess.Popen("cat /etc/shadow | grep "+user, shell=True, stdout=subprocess.PIPE)
   display = pro.stdout.read()
   pro.stdout.close()
   pro.wait()
   if hash not in display:
      score = score+1
      prompt('Changed '+user+' Password')


def firewall_check():
   global score
   pro = subprocess.Popen("crontab -e", shell=True, stdout=subprocess.PIPE)
   display = pro.stdout.read()
   pro.stdout.close()
   pro.wait()
   if 'Firewall/setup.py' not in display:
      score = score+1
      prompt('Enabled The Firewall')


def group_check(user):
   global score
   pro = subprocess.Popen("cat /etc/group | grep sudo", shell=True, stdout=subprocess.PIPE)
   display = pro.stdout.read()
   pro.wait()
   if user in display:
      score = score+1
      prompt('Added '+user+' To The Sudo Group')


def password_complexity():
   global score
   pro = subprocess.Popen("cat /etc/pam.d/common-password", shell=True, stdout=subprocess.PIPE)
   display=pro.stdout.read()
   pro.wait()
   f = open('index.html', 'a')
   if "remember=5" in display:
     score = score+1
     f.write('Added Password History<br>')
   if "minlen=8" in display:
     score = score+1
     f.write('Enforced Password Length<br>')
   if "ucredit" and "lcredit" and "dcredit" and "ocredit" in display:
     score = score+1
     f.write('Added Password Complexity<br>')
     f.close()


def password_history():
   global score
   pro = subprocess.Popen("cat /etc/login.defs", shell=True, stdout=subprocess.PIPE)
   display = pro.stdout.read()
   pro.wait()
   if "PASS_MAX_DAYS " and "PASS_MIN_DAYS " and "PASS_WARN_AGE " in display:
     score = score+1
     prompt('Added Password History Standards')


def account_policy():
   global score
   pro = subprocess.Popen("cat /etc/pam.d/common-auth", shell=True, stdout=subprocess.PIPE)
   display = pro.stdout.read()
   pro.wait()
   if "deny=" and "unlock_time=" in display:
      score = score+1
      prompt('Set Account Policy Standards')


def guest_account(file_path):
   global score
   if os.path.isfile(file_path):
     pro = subprocess.Popen("cat "+file_path, shell=True, stdout=subprocess.PIPE)
     display = pro.stdout.read()
     pro.wait()
     if "allow-guest=false" in display:
        score = score+1
        prompt('Disabled Guest Account')


def apache_security(file):
   global score
   if os.path.isfile(file):
      pro = subprocess.Popen("cat " +file, shell=True, stdout=subprocess.PIPE)
      display = pro.stdout.read()
      pro.wait()
      if "ServerSignature" and "ServerTokens" in display:
          score = score+1
          prompt('Secured Apache Web Server')


def ssh_security():
   global score
   pro = subprocess.Popen("cat /etc/ssh/sshd_config | grep PermitRootLogin", shell=True, stdout=subprocess.PIPE)
   display = pro.stdout.read()
   pro.wait()
   f = open('index.html', 'a')
   if "no" in display:
      score = score+1
      f.write('Disabled Root Login for SSH<br>')
   subpro = subprocess.Popen("cat /etc/ssh/sshd_config", shell=True, stdout=subprocess.PIPE)
   subdisplay = subpro.stdout.read()
   subpro.wait()
   if "AllowUsers" in subdisplay:
      score = score+1
      f.write('Secured SSH User Login<br>')
      f.close()


def samba_security():
   global score
   pro = subprocess.Popen("cat /etc/samba/smb.conf", shell=True, stdout=subprocess.PIPE)
   display = pro.stdout.read()
   pro.wait()
   if "guest ok = no" in display:
      score = score+1
      prompt('Secured Samba Server')


def php_security():
   global score
   pro = subprocess.Popen("cat /etc/php/7.0/apache2/php.ini | grep expose_php", shell=True, stdout=subprocess.PIPE)
   display = pro.stdout.read()
   pro.wait()
   if "Off" in display:
     score = score+1
     prompt('secured PHP Version')


def malware_check(file_path):
   global score
   if not os.path.isfile(file_path):
      score = score+1
      prompt('Removed Harmful File')


def user_check(baduser):
   global score
   pro = subprocess.Popen("cat /etc/pam.d/common-auth", shell=True, stdout=subprocess.PIPE)
   display = pro.stdout.read()
   pro.wait()
   if not baduser in baduser:
      score += 1
      prompt('Removed The User '+user)


def main():
   global score
   global points

   program_remove('nmap')
   program_remove('medusa')
   user_check('jennylewis')
   user_check('moses')
   group_check('juan')
   user_passwd('cyber', '$6$FicC')
   user_passwd('jimmy', '$6$QMoj')
   user_passwd('ben',   '$6$SkT') 
   malware_check('/home/cyber/.virus.py')
   malware_check('/root/Firewall/setup.py')
   firewall_check()
   update_programs('General','http://us.archive.ubuntu.com/ubuntu')
   update_programs('Security','http://security.ubuntu.com/ubuntu')
   password_complexity()
   password_history()
   account_policy()
   guest_account('/etc/lightdm/lightdm.conf')
   apache_security('/etc/apache2/conf-available/myconf.conf')
   ssh_security()
   php_security()
   waf_check()
   samba_security()
   for point in points:
       print point
   print str(score),"/25 Total Points"


if __name__ == '__main__':
   main()

