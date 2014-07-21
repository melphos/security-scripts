#!/bin/bash

# analyze_hosts - Scans one or more hosts on security vulnerabilities
#
# Copyright (C) 2012-2014 Peter Mosmans
#                         <support AT go-forward.net>
#
# This source code (shell script) is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# TODO: - add: option to only list commands, don't execute them
#       - change: use base options
#       - add: make logging of output default
#       - add: grep on errors of ssh script output
#       - add: check installation (whether all tools are present)
#       - change: refactor looping of ports
#       - change: iterate --ssl commands per port instead of per tool
#       - change: make script Bash < 4 proof
#       - add: show SSL certificate name


NAME="analyze_hosts"

# statuses
declare ERROR=-1
declare UNKNOWN=0
declare OPEN=1 UP=1 NONEWLINE=1 BASIC=1
declare ADVANCED=2
declare ALTERNATIVE=4

# logging and verboseness
declare NOLOGFILE=-1
declare QUIET=1
declare STDOUT=2
# Error messages are shown when VERBOSE
declare VERBOSE=4
declare LOGFILE=8
declare RAWLOGS=16
declare SEPARATELOGS=32
declare COMMAND=64

# scantypes
declare -i dnstest=$UNKNOWN fingerprint=$UNKNOWN nikto=$UNKNOWN
declare -i portscan=$UNKNOWN sshscan=$UNKNOWN sslscan=$UNKNOWN
declare -i trace=$UNKNOWN whois=$UNKNOWN webscan=$UNKNOWN

# defaults
declare cipherscan=/usr/local/bin/cipherscan/cipherscan
declare nmap=$(which nmap)
declare openssl="openssl"
#[[ ! -e $openssl ]] && openssl=$(which openssl)
declare -i loglevel=$STDOUT
declare -i timeout=30
declare webports=80,443
declare sslports=443,465,993,995,3389

# statuses
declare -i hoststatus=$UNKNOWN portstatus=$UNKNOWN
datestring=$(date +%Y-%m-%d)
workdir=/tmp

# colours
declare BLUE='\E[1;49;96m' LIGHTBLUE='\E[2;49;96m'
declare RED='\E[1;49;31m' LIGHTRED='\E[2;49;31m'
declare GREEN='\E[1;49;32m' LIGHTGREEN='\E[2;49;32m'

################################################################################
### Functions ##################################################################
################################################################################

################################################################################
# prints text on screen in color
#
# Arguments: 1 text
#            2 color
#           [3 $NONEWLINE]
################################################################################
prettyprint() {
    (($loglevel&$QUIET)) && return
    [[ -z $nocolor ]] && echo -ne $2
    if [[ "$3" == "$NONEWLINE" ]]; then
        echo -n "$1"
    else
        echo "$1"
    fi
    [[ -z $nocolor ]] && tput sgr0
}

################################################################################
# Shows error message and, if supplied, logfile containing the error
#
# Arguments: 1 errorstring
#           [2 filename]
################################################################################
err() {
    if [[ $loglevel -gt $VERBOSE ]]; then
        local errorstring=$1
        local filename=$2
        [[ -z $nocolor ]] && echo -ne $RED
        [[ $loglevel -gt $VERBOSE ]] && echo "[$(date +'%H:%M:%S')] Error: $errorstring" >&2
        [[ -z $nocolor ]] && tput sgr0
        [[ -s $filename ]] && cat $filename
    fi
}

usage() {
    local realpath=$(dirname $(readlink -f $0))
    if [[ -d $realpath/.git ]]; then
        pushd $realpath 1>/dev/null 2>&1
        local branch=$(git rev-parse --abbrev-ref HEAD)
        local commit=$(git log|head -1|awk '{print $2}'|cut -c -10)
        popd
        prettyprint "$NAME (git) from ${branch} branch commit ${commit}" $BLUE
    else
        prettyprint "$NAME version $VERSION" $BLUE
    fi
    prettyprint "      (c) 2012-2014 Peter Mosmans [Go Forward]" $LIGHTBLUE
    prettyprint "      Licensed under the Mozilla Public License 2.0" $LIGHTBLUE
    echo ""
    echo " usage: $0 [OPTION]... [HOST]"
    echo ""
    echo "Scanning options:"
    echo " -a, --all               perform all basic scans" 
    echo "     --max               perform all advanced scans (more thorough)" 
    echo " -b, --basic             perform basic scans (fingerprint, ssl, trace)"
    echo " -c                      print command to be executed"
    echo "                         results of HOST matches regexp FILTER"
    echo "     --dns               test for recursive query"
    echo " -f                      perform web fingerprinting (all webports)"
    echo "     --fingerprint       perform all web fingerprinting methods"
    echo " -h, --header            show webserver headers (all webports)"
    echo " -n, --nikto             nikto webscan (all webports)"
    echo " -p                      nmap portscan (top 1000 TCP ports)"
    echo "     --ports             nmap portscan (all ports, TCP and UDP)"
    echo " -s                      check SSL configuration"
    echo "     --ssl               perform all SSL configuration checks"
    echo "     --sslcert           show details of SSL certificate"
    echo "     --timeout=SECONDS   change timeout for ciphercan (default=$timeout)"
    echo "     --ssh               perform SSH configuration checks"
    echo " -t                      check webserver for HTTP TRACE method"
    echo "     --trace             perform all HTTP TRACE method checks"
    echo " -w, --whois             perform WHOIS lookup for (hostname and) IP address"
    echo " -W                      confirm WHOIS results before continuing scan"
    echo "     --filter=FILTER     only proceed with scan of HOST if WHOIS"
    echo "     --wordlist=filename scan webserver for existence of files in filename"
    echo ""
    echo "Port selection (comma separated list):"
    echo "     --webports=PORTS    use PORTS for web scans (default $webports)"
    echo "     --sslports=PORTS    use PORTS for ssl scans (default $sslports)"
    echo ""
    echo "Logging and input file:"
    echo " -d, --directory=DIR     location of temporary files (default /tmp)"
    echo " -i, --inputfile=FILE    use a file containing hostnames"
    echo " -l, --log               log each scan in a separate logfile"
    echo "     --nocolor           don't use fancy colors in screen output" 
    echo " -o, --output=FILE       concatenate all results into FILE"
    echo " -q, --quiet             quiet"
    echo " -v, --verbose           show server responses"
    echo ""
    echo " -u                      update this script (if it's a cloned repository)"
    echo "     --update            force update (overwrite all local modifications)"
    echo "     --version           print version information and exit"
    echo ""
    prettyprint "                         BLUE: status messages" $BLUE
    prettyprint "                         GREEN: secure settings" $GREEN
    prettyprint "                         RED: possible vulnerabilities" $RED
    echo ""
    echo " [HOST] can be a single (IP) address, an IP range, eg. 127.0.0.1-255"
    echo " or multiple comma-separated addressess"
    echo ""
    echo "example: $0 -a --filter Amazon www.google.com"
    echo ""
}

################################################################################
# Checks if tool_name exists and sets GLOBAL variables
# Should always be concluded with a purgelogs
# Arguments: 1 tool_name
#
# Changes the following GLOBAL variables: 1 logfile
#                                         2 tool
################################################################################
setlogfilename() {
    if [[ ! -z $1 ]] && type $1 >/dev/null 2>&1; then
        tool=$(basename $1)
        logfile=$workdir/${target}_${tool}_${datestring}.txt
    else
        err "The program $1 could not be found"
        tool=$ERROR
    fi
}

# purgelogs logfile [LOGLEVEL]
# purges the current logfile
# if LOGLEVEL = VERBOSE then show log on screen
purgelogs() {
    local currentloglevel=$loglevel
    if [[ ! -z $1 ]]; then let "loglevel=loglevel|$1"; fi
    if [[ ! -z "$$logfile" ]] && [[ -f "$logfile" ]]; then
        if (($loglevel&$VERBOSE)); then
            if [[ -s "$logfile" ]]; then 
                showstatus "$(grep -v '^#' $logfile)"
                showstatus ""
            fi
        fi
        if (($loglevel&$RAWLOGS)); then
            grep -v '^[#%]' $logfile >> $outputfile
        fi
        if !(($loglevel&$SEPARATELOGS)); then rm $logfile 1>/dev/null 2>&1; fi
    fi
    tool=$ERROR
    loglevel=$currentloglevel
}

# showstatus message [COLOR] [LOGFILE|NOLOGFILE|NONEWLINE]
#                    COLOR: color of message
#                    LOGFILE: only write contents to logfile
#                    NOLOGFILE: don't log contents to logfile
#                    NONEWLINE: don't echo new line character

showstatus() {
    if [[ ! -z "$2" ]]; then
        case "$2" in
            $LOGFILE)
                (($loglevel&$LOGFILE)) && echo "$1" >> $outputfile;;
            $NOLOGFILE)
                !(($loglevel&$QUIET)) && echo "$1";;
            $NONEWLINE)
                !(($loglevel&$QUIET)) && echo -n "$1"
                (($loglevel&$LOGFILE)) && echo -n "$1" >> $outputfile;;
            (*) 
                prettyprint "$1" $2 $3
                (($loglevel&$LOGFILE)) && echo "$1" >> $outputfile;;
        esac
    else
        !(($loglevel&$QUIET)) && echo "$1"
        (($loglevel&$LOGFILE)) && echo "$1" >> $outputfile
    fi
}

do_update() {
    local realpath=$(dirname $(readlink -f $0))
    local branch="unkown"
    local commit="unknown"
    if [[ -d $realpath/.git ]]; then
        setlogfilename "git"
        if (($tool!=$ERROR)); then
            local status=$UNKNOWN
            pushd $realpath 1>/dev/null 2>&1
            branch=$(git rev-parse --abbrev-ref HEAD)
            commit=$(git log|head -1|awk '{print $2}'|cut -c -10)
            showstatus "current version: $VERSION (${branch} branch commit ${commit})"
            if [[ ! -z "$1" ]]; then
                showstatus "forcing update, overwriting local changes"
                git fetch origin master 1>$logfile 2>&1
                git reset --hard FETCH_HEAD 1>>$logfile 2>&1
            else
                git pull 1>$logfile 2>&1
            fi
            commit=$(git log|head -1|awk '{print $2}'|cut -c -10)
            grep -Eq "error: |Permission denied" $logfile && status=$ERROR
            grep -q "Already up-to-date." $logfile && status=$OPEN
            popd 1>/dev/null 2>&1
        else
            status=$ERROR
        fi
        case $status in
            $ERROR) showstatus "error updating $0" $RED;;
            $UNKNOWN) showstatus "succesfully updated to $(awk '{FS="\""}/^VERSION=/{print $2}' $0) (commit ${commit})" $GREEN;;
            $OPEN) showstatus "already running latest version" $BLUE;;
        esac
        purgelogs
        exit 0
    else
        showstatus "Sorry, this doesn't seem to be a git repository"
        showstatus "Please clone the repository using the following command: "
        showstatus "git clone https://github.com/PeterMosmans/security-scripts.git"
    fi;
}

startup() {
    flag=$OPEN
    trap cleanup EXIT
    showstatus "$NAME version $VERSION starting on $(date +%d-%m-%Y' at '%R)"
    if (($loglevel&$LOGFILE)); then
        if [[ -n $appendfile ]]; then
            showstatus "appending to existing file $outputfile"
        else
            showstatus "logging to $outputfile"
        fi
    fi
    showstatus "scanparameters: $options" $LOGFILE
    [[ -n "$workdir" ]] && pushd $workdir 1>/dev/null 2>&1
}

version() {
    curl --version
    echo ""
    nikto -Version
    echo ""
    $nmap -V
    echo ""
    $openssl version -a|sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g"
    echo ""
    prettyprint "$NAME version $VERSION" $BLUE
    prettyprint "      (c) 2013-2014 Peter Mosmans [Go Forward]" $LIGHTBLUE
    prettyprint "      Licensed under the Mozilla Public License 2.0" $LIGHTBLUE
    echo ""
}

checkifportopen() {
    portstatus=$UNKNOWN
    if [[ -s "$portselection" ]]; then
        portstatus=$ERROR
        grep -q " $1/open/" $portselection && portstatus=$OPEN
    fi
}

do_dnstest() {
    setlogfilename "dig"
    if (($tool!=$ERROR)); then
        local status=$UNKNOWN
        local ports=53
        showstatus "trying recursive dig... " $NONEWLINE
        dig google.com @$target 1>$logfile 2>&1 </dev/null
        grep -q "ANSWER SECTION" $logfile && status=$OPEN
        if (($status==$OPEN)); then
            showstatus "recursion allowed" $RED
        else
            showstatus "no recursion or answer detected" $GREEN
        fi
        purgelogs
    fi
}

do_fingerprint() {
    if (($fingerprint==$BASIC)) || (($fingerprint==$ADVANCED)); then
        setlogfilename "whatweb"
        if (($tool!=$ERROR)); then
            for port in ${webports//,/ }; do
                setlogfilename "whatweb"
                showstatus "performing whatweb fingerprinting on $target port $port... "
                if [[ ! $sslports =~ $port ]]; then
                    whatweb -a3 --color never http://$target:$port --log-brief $logfile 1>/dev/null 2>&1
                else
                    whatweb -a3 --color never https://$target:$port --log-brief $logfile 1>/dev/null 2>&1
                fi
                purgelogs $VERBOSE
            done
        fi
    fi

    if (($fingerprint==$ADVANCED)) || (($fingerprint==$ALTERNATIVE)); then
        setlogfilename "curl"
        if (($tool!=$ERROR)); then
            for port in ${webports//,/ }; do
                setlogfilename "curl"
                checkifportopen $port
                if (($portstatus==$ERROR)); then
                    showstatus "$target port $port closed" $BLUE
                else
                    showstatus "retrieving headers from $target port $port... " $NONEWLINE
                    if [[ ! $sslports =~ $port ]]; then
                        curl -A "$NAME" -q --insecure -m 10 --dump-header $logfile http://$target:$port 1>/dev/null 2>&1 || showstatus "could not connect to $target port $port" $BLUE $NONEWLINE
                    else
                        curl -A "$NAME" -q --insecure -m 10 --dump-header $logfile https://$target:$port 1>/dev/null 2>&1 || showstatus "could not connect to $target port $port" $BLUE $NONEWLINE
                    fi
                    showstatus ""
                    purgelogs $VERBOSE
                fi
            done
        fi
    fi
}

do_nikto() {
    setlogfilename "nikto"
    if (($tool!=$ERROR)); then
        [[ $target =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] && showstatus "FQDN preferred over IP address"
        for port in ${webports//,/ }; do
            setlogfilename "nikto"
            checkifportopen $port
            if (($portstatus==$ERROR)); then
                showstatus "port $port closed" $GREEN
            else
                showstatus "performing nikto webscan on port $port... "
                nikto -host $target:$port -Format txt -output $logfile 1>/dev/null 2>&1 </dev/null
            fi
            purgelogs $VERBOSE
        done
    fi
}

do_portscan() {
    setlogfilename "nmap"
    hoststatus=$UNKNOWN
    if (($portscan>=$ADVANCED)); then
        showstatus "performing advanced nmap portscan (all ports)... " $NONEWLINE
        $nmap --open -p- -sV -sC -oN $logfile -oG $portselection $target 1>/dev/null 2>&1 </dev/null
    else
        showstatus "performing nmap portscan... " $NONEWLINE
        $nmap --open -sS -sU -sV -sC -oN $logfile -oG $portselection $target 1>/dev/null 2>&1 </dev/null
    fi
    grep -q "0 hosts up" $portselection || hoststatus=$UP
    if (($hoststatus<$UP)); then
        showstatus "host down" $BLUE
    else
        showstatus "host is up" $BLUE
    fi
    purgelogs $VERBOSE
}

do_sshscan() {
    if (($sshscan>=$BASIC)); then
        setlogfilename $nmap
        local portstatus=$UNKNOWN
        local ports=22
        showstatus "trying nmap SSH scan on $target port $ports... " $NONEWLINE
        $nmap -Pn -p $ports --open --script banner.nse,sshv1.nse,ssh-hostkey.nse,ssh2-enum-algos.nse -oN $logfile $target 1>/dev/null 2>&1 </dev/null
        grep -q " open " $logfile && portstatus=$OPEN
        if (($portstatus<$OPEN)); then
            showstatus "port closed" $BLUE
            purgelogs
        else
            showstatus "port open" $BLUE
            purgelogs $VERBOSE
        fi
    fi
}

################################################################################
# Executes command [and pre-filters the result using awk]
#
# Arguments: 1 command
#           [2 output_file]
#           [2 awk_command]
################################################################################
execute_command() {
    local command=$1
    local output=${2:-/dev/null}
    local filter=$3
    # TODO: check if command should be executed, displayed or both
    (($loglevel&$COMMAND)) && echo "executing ${command}"
    timeout $timeout $command 1> $output 2>/dev/null || err "executing $command"
    if [[ ! -z $filter ]] && [[ -s $output ]]; then
        #        full_result=$(mktemp -q $NAME.XXXXXXX --tmpdir=$workdir)
        full_result=$(mktemp -q $NAME.XXXXXXX)
        mv -f $output $full_result
        awk "${filter}" $full_result > $output
        rm -f $full_result
    fi
}

do_sslscan() {
    setlogfilename $cipherscan
    if (($sslscan>=$BASIC)) && [[ $tool != $ERROR ]]; then
       for port in ${sslports//,/ }; do
           checkifportopen $port
           if (($portstatus==$ERROR)); then
               showstatus "port $port closed" $BLUE
               return
           fi
           showstatus "performing cipherscan on $target port $port... " $NONEWLINE
           execute_command "$cipherscan -o $openssl $target:$port" $logfile '/^[0-9]/{print $2,$3}'
           if [[ -s $logfile ]] ; then
               showstatus ""
               showstatus "$(awk '/(ADH|RC4|IDEA|SSLv2|EXP|MD5|NULL| 40| 56)/{print $1,$2}' $logfile)" $RED
           else
               showstatus "could not connect" $BLUE
           fi
           purgelogs
           parse_cert $target $port
       done
    fi
    purgelogs

    setlogfilename $nmap
    if (($sslscan>=$ADVANCED)) && [[ $tool != $ERROR ]]; then
        showstatus "performing nmap sslscan on $target ports $sslports... "
        execute_command "$nmap -p $sslports --script ssl-enum-ciphers,ssl-heartbleed,rdp-enum-encryption --open $target -oN $logfile" /dev/null '/!^#/'
        if [[ -s $logfile ]] ; then
            showstatus "$(awk '/( - )(broken|weak|unknown)/{print $2}' $logfile)" $RED
        else
            showstatus "could not connect to $target ports $sslports" $BLUE
        fi
    fi
    purgelogs
}

################################################################################
# Obtains a x.509 certificate and shows whether the dates are valid
#
# Arguments: 1 target
#            2 port
################################################################################
parse_cert() {
    local target=$1
    local port=$2
    setlogfilename $openssl
    if [[ "$tool" != "$ERROR" ]]; then
        showstatus "trying to retrieve SSL x.509 certificate on ${target}:${port}... " $NONEWLINE
        #        certificate=$(mktemp -q $NAME.XXXXXXX --tmpdir=$workdir)
        certificate=$(mktemp -q $NAME.XXXXXXX)
        echo Q | $openssl s_client -connect $target:$port -servername $target 2>/dev/null 1>$certificate
        if [[ -s $certificate ]]; then
            showstatus "certificate received" $BLUE
            showstatus "$($openssl x509 -noout -subject -nameopt multiline -in $certificate 2>/dev/null)"
            startdate=$($openssl x509 -noout -startdate -in $certificate 2>/dev/null|cut -d= -f 2)
            enddate=$($openssl x509 -noout -enddate -in $certificate 2>/dev/null|cut -d= -f 2)
            parsedstartdate=$(date --date="$startdate" +%Y%m%d)
            parsedenddate=$(date --date="$enddate" +%Y%m%d)
            localizedstartdate=$(date --date="$startdate" +%d-%m-%Y)
            localizedenddate=$(date --date="$enddate" +%d-%m-%Y)
            if [[ $parsedstartdate -gt $(date +%Y%m%d) ]]; then
                showstatus "certificate is not valid yet, valid from ${localizedstartdate} until ${localizedenddate}" $RED
            else
                    if [[ $parsedenddate -lt $(date +%Y%m%d) ]]; then
                        showstatus "certificate has expired on ${localizedenddate}" $RED
                    else
                        showstatus "certificate is valid between ${localizedstartdate} and ${localizedenddate}" $GREEN
                    fi
                fi
        else
            showstatus "failed" $RED
        fi
        rm -f $certificate 1>/dev/null
    fi
    purgelogs
}

do_trace() {
    setlogfilename "curl"
    if (($tool!=$ERROR)); then
        for port in ${webports//,/ }; do
            setlogfilename "curl"
            checkifportopen $port
            showstatus "trying TRACE method on $target port $port... " $NONEWLINE
            if (($portstatus==$ERROR)); then
                showstatus "$target port $port closed" $GREEN
            else
                local prefix="http://"
                [[ $sslports =~ $port ]] && prefix="--insecure https://"
                curl -q -s -A "$NAME" -i -m 30 -X TRACE -o $logfile $prefix$target:$port/ 1>/dev/null 2>&1
                if [[ -s $logfile ]]; then
                    status=$(awk 'NR==1 {print $2}' $logfile)
                    if (($status==200)); then
                        showstatus "TRACE enabled on port $port" $RED
                    else
                        showstatus "disabled (HTTP $status)" $GREEN
                    fi
                else
                    showstatus "could not connect" $BLUE
                fi
            fi
            purgelogs
        done
    fi

    if (($trace>=$ADVANCED)); then
        setlogfilename $nmap
        showstatus "trying nmap TRACE method on ports $webports... " $NONEWLINE
        $nmap -p$webports --open --script http-trace -oN $logfile $target 1>/dev/null 2>&1 </dev/null
	if [[ -s $logfile ]]; then
            status="$(awk '{FS="/";a[++i]=$1}/TRACE is enabled/{print "TRACE enabled on port "a[NR-1]}' $logfile)"
            if [[ -z "$status" ]]; then
                grep -q " open " $logfile && status=$OPEN
                if [[ $OPEN -eq $status ]]; then
                    showstatus "disabled"  $GREEN
                else
                    showstatus "could not connect" $BLUE
                fi
            else
                showstatus "$status" $RED
            fi
        fi
        purgelogs
    fi
}

do_webscan() {
    setlogfilename "curl"
    if (($tool!=$ERROR)); then
        for port in ${webports//,/ }; do
            showstatus "trying list $wordlist on $target port $port... "
            local prefix="http://"
            [[ $sslports =~ $port ]] && prefix="--insecure https://"
            if [[ -s "$wordlist" ]]; then
                while read word; do
                    setlogfilename "curl"
                    curl -q -s -A "$NAME" -I -m 10 -o $logfile $prefix$target/$word </dev/null
                    if [[ -s $logfile ]]; then
                        status=$(awk 'NR==1 {print $2}' $logfile)
                        (($status==200)) && showstatus "$target:$port/$word returns 200 OK" $RED
                    fi
                    purgelogs
                done < "$wordlist"
            else
                showstatus "could not open $wordlist" $RED
            fi
        done
    fi
}

execute_all() {
    #    portselection=$(mktemp -q $NAME.XXXXXXX --tmpdir=$workdir)
        portselection=$(mktemp -q $NAME.XXXXXXX)
    if (($whois>=$BASIC)); then
        local nomatch=
        local ip=
        setlogfilename "whois"
        if [[ $target =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            ip=$target
            local reverse=$(host $target|awk '{print $5}'|sed s'/[.]$//')
            if [[ "$reverse" == "3(NXDOMAIN)" ]] ; then
                showstatus "$target does not resolve to a PTR record" 
            else
                showstatus "$target resolves to " $NONEWLINE
                showstatus $reverse $BLUE
            fi
        else
            whois ${target#*.} > $logfile
            grep -q "No match for" $logfile && whois ${target%%*.} > $logfile
            # not all whois servers use the same formatting
            showstatus "$(grep -iE '^(registra|date|admin |tech|name server)(.*):(.*)[^ ]$' $logfile)"
            showstatus "$(awk '/Registrar( Technical Contacts)*:[ ]*$|(Domain )*[Nn]ameservers:[ ]*$|Technical:[ ]*$/{s=1}s; /^$/{s=0}' $logfile)"
            ip=$(host -c IN $target|awk '/address/{print $4}'|head -1)
            if [[ ! -n "$ip" ]]; then
                showstatus "$target does not resolve to an IP address - aborting scans" $RED
                purgelogs
                return
            else
                showstatus "$target resolves to $ip"
            fi
        fi
        whois -H $ip > $logfile
        showstatus "$(grep -iE '^(inetnum|netrange|netname|nettype|descr|orgname|orgid|originas|country|origin):(.*)[^ ]$' $logfile)"
        if [[ -n "$filter" ]]; then
            if grep -qiE "^(inetnum|netrange|netname|nettype|descr|orgname|orgid|originas|country|origin):.*($filter)" $logfile; then
                showstatus "WHOIS info matches $filter - continuing scans" $GREEN
            else
                showstatus "WHOIS info doesn't match $filter - aborting scans on $target" $RED
                purgelogs
                return
            fi
        fi

        (($whois&$ADVANCED)) && read -p "press ENTER to continue: " failsafe < /dev/stdin
        purgelogs
    fi

    (($portscan>=$BASIC)) && do_portscan
    (($dnstest>=$BASIC)) && do_dnstest
    (($fingerprint>=$BASIC)) && do_fingerprint
    (($nikto>=$BASIC)) && do_nikto
    (($sshscan>=$BASIC)) && do_sshscan
    (($sslscan>=$BASIC)) && do_sslscan
    (($trace>=$BASIC)) && do_trace
    (($webscan>=$BASIC)) && do_webscan
    [[ -e "$portselection" ]] && rm $portselection 1>/dev/null 2>&1
}

looptargets() {
    if [[ -s "$inputfile" ]]; then
        total=$(grep -c . $inputfile)
        local counter=1
        while read target; do
            if [[ ! -z "$target" ]]; then
               showstatus ""
               showstatus "working on " $NONEWLINE
               showstatus "$target" $BLUE $NONEWLINE
               showstatus " ($counter of $total)"
               let counter=$counter+1
               execute_all
            fi
        done < "$inputfile"
    else
        showstatus ""
        showstatus "working on " $NONEWLINE
        showstatus "$target" $BLUE
        execute_all
    fi
}

abortscan() {
    flag=$ERROR
     if (($tool!=$ERROR)); then
         showstatus ""
         showstatus "interrupted $tool while working on $target..." $RED
         purgelogs
         prettyprint "press Ctrl-C again to abort scan, or wait 10 seconds to resume" $BLUE
         sleep 10 && flag=$OPEN
     fi
     ((flag==$ERROR)) && exit 1
}

cleanup() {
    trap '' EXIT INT QUIT
    if [[ ! -z $tool ]] && [[ "$tool" != "$ERROR" ]]; then 
        showstatus "$tool interrupted..." $RED
        purgelogs
    fi
    showstatus "cleaning up temporary files..."
    [[ -e "$portselection" ]] && rm "$portselection"
    [[ -e "$tmpfile" ]] && rm "$tmpfile"
    [[ -n "$workdir" ]] && popd 1>/dev/null
    (($loglevel&$LOGFILE)) && showstatus "logged to $outputfile" $NOLOGFILE
    showstatus "ended on $(date +%d-%m-%Y' at '%R)"
    exit
}

################################################################################
### Main program ###############################################################
################################################################################

trap abortscan INT
trap cleanup QUIT

which tput 1>/dev/null 2>&1 || nocolor=TRUE
if ! options=$(getopt -s bash -o acd:fhi:lno:pqstuvwWy -l dns,directory:,filter:,fingerprint,header,inputfile:,log,max,nikto,nocolor,output:,ports,quiet,ssh,ssl,sslcert,sslports:,timeout:,trace,update,version,webports:,whois,wordlist: -- "$@") ; then
    usage
    exit 1
fi 

eval set -- $options
if [[ "$#" -le 1 ]]; then
    usage
    exit 1
fi

while [[ $# -gt 0 ]]; do
    case $1 in
        -a|--all) 
            dnstest=$BASIC
            fingerprint=$BASIC
            nikto=$BASIC
            portscan=$BASIC
            sshscan=$BASIC
            sslscan=$BASIC
            trace=$BASIC
            whois=$BASIC;;
        --allports) portscan=$ADVANCED;;
        --dns) dnstest=$ADVANCED;;
        -c) let "loglevel=loglevel|$COMMAND";;
        -f) fingerprint=$BASIC;;
        --fingerprint) fingerprint=$ADVANCED;;
        -h|--header) fingerprint=$ALTERNATIVE;;
        -d|--directory) workdir=$2
            shift ;;
        --filter) filter="$2"
            let "whois=whois|$BASIC"
            shift ;;
        -i|--inputfile) inputfile="$2"
            [[ ! $inputfile =~ ^/ ]] && inputfile=$(pwd)/$inputfile
            if [[ ! -s "$inputfile" ]]; then
                err "cannot find $inputfile"
                exit 1
            fi           
            shift ;;
        -l) log="TRUE";;
        --max)             
            dnstest=$ADVANCED
            fingerprint=$ADVANCED
            nikto=$ADVANCED
            portscan=$ADVANCED
            sshscan=$ADVANCED
            sslscan=$ADVANCED
            trace=$ADVANCED
            whois=$ADVANCED;; 
        -n) nikto=$BASIC;;
        --nikto) nikto=$ADVANCED;;
        --nocolor) nocolor=TRUE;;
        -o|--output)
            let "loglevel=loglevel|$LOGFILE"
            outputfile=$2
            [[ ! $outputfile =~ ^/ ]] && outputfile=$(pwd)/$outputfile
            [[ -s $outputfile ]] && appendfile=1
            shift ;;
        -p) portscan=$BASIC;;
        --ports) portscan=$ADVANCED;;
        --webports) webports=$2
            shift ;;
        --sslports) sslports=$2
            shift ;;
        -q|--quiet) let "loglevel=loglevel|$QUIET";;
        -s) sslscan=$BASIC;;
        --ssh) sshscan=$BASIC;;
        --ssl) sslscan=$ADVANCED;;
        --sslcert) sslscan=$ALTERNATIVE;;
        -t) trace=$BASIC;;
        --timeout) timeout=$2
            shift ;;
        --trace) trace=$ADVANCED;;
        -u) do_update && exit 0;;
        --update) do_update 1 && exit 0;;
        -v) let "loglevel=loglevel|$VERBOSE";;
        --version) version;
                   exit 0;;
        -w|--whois) whois=$BASIC;;
        -W) let "whois=whois|$ADVANCED";;
        --wordlist) let "webscan=webscan|$BASIC"
            wordlist=$2
            [[ ! $wordlist =~ ^/ ]] && wordlist=$(pwd)/$wordlist
            shift ;;
        (--) shift; 
             break;;
        (-*) echo "$0: unrecognized option $1" 1>&2; exit 1;;
        (*) break;;
    esac
    shift
done

#if ! type $nmap >/dev/null 2>&1; then
#    err "the program nmap is needed but could not be found"
#    exit
#fi

if [[ ! -s "$inputfile" ]]; then
    if [[ ! -n "$1" ]]; then
        echo "Nothing to do... no target specified"
        exit
    fi
    umask 177
    if [[ -n "$workdir" ]]; then 
        [[ -d $workdir ]] || mkdir $workdir 1>/dev/null 2>&1
    fi
    tmpfile=$(mktemp -q $NAME.XXXXXXX --tmpdir=$workdir)
    if [[ $1 =~ -.*[0-9]$ ]]; then
        $nmap -nsL $1 2>/dev/null|awk '/scan report/{print $5}' >$tmpfile
        inputfile=$tmpfile
    fi
    if [[ $1 =~ , ]]; then
        for targets in ${1//,/ }; do
            echo $targets >> $tmpfile
        done
        inputfile=$tmpfile
    fi
fi

target=$1
startup
looptargets
