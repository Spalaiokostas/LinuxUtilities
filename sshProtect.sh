#!/bin/bash
##########################################################################
# Title     : sshProtect.sh
# Author    : Spyros Palaiokostas
# Date      : 7/12/14
##########################################################################
# Description
#   Active protection against ssh bruteforce
#
#   This is a script that watches for failed ssh login attempts and if
#   a certain number of attempts has been made from the same ip, then
#   we proceed to drop all packets at port 22 (default ssh port) for
#   a certain amount of time.
##########################################################################

# Set Script Name variable
SCRIPT=`basename ${BASH_SOURCE[0]}`

# initialize default variables 
interval=60
maxFailedLogins=9
BanDuration=5

Usage="Usage: $SCRIPT [-i interval] [-M maxFailedLogins] [ -A BanDuration]"

# Help function
function HELP {
    echo -e "\nHelp documentation for ${SCRIPT}"
    echo "Basic usage:$SCRIPT"
    echo "Command line arguments are optional. The following arguments are recognized."
    echo -e "\t-i  --Sets the value for option interval. Default is 60 seconds"
    echo -e "\t-M  --Sets the value for option maxFailedLogins. Default is 9"
    echo -e "\t-A  --Sets the value for option BanDuration. Default is 5 minutes\n"
    echo "Interval is a number of seconds that must pass from the last failed login in order to reduce the counter"
    echo "maxFailedLogins is the number of failed logins that results to deny access to ssh port"
    echo "BanDuration is the number of minutes that must pass in order to allow again access from the host to ssh port"
    echo -e "\nReports about denied host are saved at /var/tmp at ~/sshProtect.reports"
exit
}

# use getopts to get optional arguments from command line
while getopts "i:M:A:h" opt; do
  case "$opt" in
    i)
        interval=$OPTARG ;;
    M)
        maxFailedLogins=$OPTARG;;
    A)
        BanDuration=$OPTARG ;;
    h)
        HELP ;;
    \?)
        echo $Usage
        echo "Type $SCRIPT -h for more"
        exit ;;
  esac
done

# shift all arguments that getopts recognized
shift $((OPTIND-1))
  
# if there are more arguments then exit  
if [ $# -ne 0 ]; then
    echo $Usage
    "Type $SCRIPT -h for more"
    exit 
fi

# check if inotifywait is installed, if not exit
if ! hash inotifywait 2>/dev/null; then
    echo "This script requires inotifywait but it's not installed...Aborting."
    exit 
fi

# check if script was executed with root privilages
if [ "$EUID" -ne 0 ]
  then echo "This script requires root privilages..Please run as root"
  exit 
fi

# create assosiative arrays..
# use array "count" to count number of times that an ip address has failed to log in
# use array "time" to when was the last failed attempt for each ip address
declare -A count
declare -A time

# inotifywait waits for a modify event at /var/log/auth.log
# if an event has occurred when go inside the while loop
while inotifywait -qq -e modify /var/log/auth.log; do 

    # proceed only if the event that occurred was a log about a failed ssh login
    if failed_ssh="$(tail -n1 /var/log/auth.log | grep ssh.*Failed)"; then
        # write to failed attempt to log   
        echo $failed_ssh >> $HOME/sshProtect.reports

        ip="$(echo $failed_ssh | grep -o -P '(?<=from ).*(?= port)')"
        current_time="$(date +%s)"

        # for every number of second (interval) that has passed from the last failed login
        # reduce by one the counter of failed login attempts from current ip address
        temp=$(( time[$ip] + $interval ))
        while [[ ${count[$ip]} > 0 && $current_time > $temp ]];do
            (( count[$ip]-- ))
            temp=$(( $temp + $interval ))
        done

        # increase counter and set time of current failed login
        (( count[$ip]++ ))
        time[$ip]=$current_time

        # if a number of failed logins occured (maxFailedLogins) then drop packets from the ip address 
        # for a number of minutes (BanDuration)
        # we use maxFailedLogins - 1 because counting for maxFailedLogins starts from zero (0) while natural counting for failed attempts start from one (1)
        if [ ${count[$ip]} = $maxFailedLogins ]; then
            iptables -A INPUT -s $ip -p tcp --destination-port 22 -j DROP
            echo "iptables -D INPUT -s $ip -p tcp --destination-port 22 -j DROP" | at now + $BanDuration min > /dev/null 2>&1

            # write info to file ~/sshProtect.reports
            account="$(echo $failed_ssh | grep -o -P '(?<=for ).*(?= from)')"
            echo "Host:$ip Account:$account at $(date)" >> $HOME/sshProtect.reports
        fi 
    fi
done
