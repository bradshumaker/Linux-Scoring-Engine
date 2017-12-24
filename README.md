# Linux Scoring Engine

This scoring engine has a modular aspect to it, in the sense that it can, through a few edits, can be applied
to almost any Linux image, on Debian based distributions.

My recommendation for setting up the engine:

1. Have the "bad image" already created, for simplicity sake.

2. Read and run the install script.

3. From here, edit the root user's crontab (# crontab -e) and place the line:

* * * * * export DISPLAY=:0 && export XAUTHORITY=/home/cpstudent/.Xauthority && /usr/bin/python2 /ScoringEngine/engine.py


4. Configure the engine.conf file located in the \ScoringEngine folder

5. Check the folder containing engine.py for Error_log.txt and review the Scoring_Report.html location you configured in the engine.


# Acknowledgements
This scoring engine was created is based off Moses Arocha's Linux Scoring Engine. 
Provided uder the MIT License.
