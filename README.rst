=======
temp_ssh
=======

About
------

temp_ssh is a tool to allow your current public ip address ssh access to a provided security group. It speeds up the process of temporary ssh access.

Example
--------

temp_ssh is a command line tool, below are example argurements.

CLI::

        usage: temp_ssh [ARGS] ....

        optional arguments:
          --sg SG                       Provide the security group to be updated
          --sg-clean-up SG_CLEAN_UP     Provide an security group to be cleaned up
          --env ENV                     Provide an enviroment file
          --env-clean-up ENV_CLEAN_UP   Provide an environment to be cleaned up

        temp_ssh --env Sandbox 

To make use of an environment file, populate config.json.example and convert the file to config.json. --env by deafult looks for config.json in the directory it is ran from

Install
---------

::      
 
        $ pip install temp_ssh

To Do
-----------
[] Create lambda for clean-up
