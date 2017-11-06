# Linux Scoring Engine

This scoring engine has a modular aspect to it, in the sense that it can, through a few edits, can be applied
to almost any Linux image, on Debian based distributions.

My recommendation for setting up the engine:

1. Have the "bad image" already created, for simplicity sake.

2. Copy the engine.py file to the root directory, remove all read and write permissions.

3. From here, edit the root user's crontab (# crontab -e) and place the line:

                * *  * * * python2 /directory/of/symboliclink

4. Check the folder containing engine.py for Error_log.txt and review the Scoring_Report.html location you configured in the engine.


My recommendation for setting up terminal based engine:


# Acknowledgements

 This scoring engine was created on the behalf of both Holmes and Business Careers
 
 Cyber Patriot High School teams and created for their use. This code is avaliable 
 
 for resditribution and modification of any kind, please refer to the MIT License.
 
 
