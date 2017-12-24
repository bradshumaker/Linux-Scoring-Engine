#!/bin/bash
mkdir \ScoringEngine
cp -rf * \ScoringEngine
chmod -R 711 \ScoringEngine\*
#Add the following to root's crontab with "crontab -e"
#
#* * * * * export DISPLAY=:0 && export XAUTHORITY=/home/cpstudent/.Xauthority && /usr/bin/python2 /ScoringEngine/engine.py
#
