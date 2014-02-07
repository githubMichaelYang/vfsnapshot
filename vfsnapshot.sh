#!/bin/bash
#
# Haivision Furnace system snapshot script. 
#  Collects hardware, OS, and Furnace related data for support analysis.
#  -l, --logs flags Collects all of the above including important system and Furnace logs. 
# Auth jbohnert, tpotter, ptomaszewski
# v2.1
#
# This version of the script works correctly on systems from 4.3 to 6.1
# Some results will be bad on 4.2 systems.

realuser=$(/usr/bin/who am i | /bin/sed -e 's/ .*//') #needed to asign the right owner for output files
outfile="furnace-profile-$(hostname)-$(date +%Y%m%d)-$(date +%H%M%S).txt"
logdir="furnace-system-dump-$(hostname)-$(date +%Y%m%d)-$(date +%H%M%S)"

#########Functions

#if the file exists, prefilter with grep and then grep the result. if any result return "label: result" in $result
# args: file, "grep pattern", "label", [ "prefilter"  ]
function searchinfile {
    result="";file="$1";prefilter="$4";filter="$2";label="$3"
    if [ -e "$file" ]; then
        grepres="$(/bin/grep "$prefilter" $file | /bin/grep -o -E "$filter")"
        if [ "$grepres" ]; then
            result="$label $grepres"
        fi
    fi
}

#Make a pretty border
function writeheader {
    if [ "$1" ]; then
        count=$(/bin/echo "$1" | /usr/bin/wc -c)
        border=""
        for x in $(/usr/bin/seq 0 $((count + 2 ))); do border="$border#";  done 
        /bin/echo -e "\n\n$border\n# $1 #\n$border\n" >> $outfile
    fi
}

#Write out to outfile
function write {
    if [ "$1" ]; then
        /bin/echo -e "$1" >> $outfile
    fi
}

#TP's resolution converter, modified to passthrough
#Take an input value and stick the translation in result, if any 
function vfcodeconvert {
    result=""
    if [ "$1" ]; then
        case $1 in
            2239773696) result="176x120 - QSIF"; ;;
            2332063744) result="352x240 - SIF_352"; ;;
            2399172608) result="480x240 - SIF_480"; ;;
            2399203329) result="480x480 - D1_480"; ;;
            2525032449) result="720x480 - D1_720"; ;;
            2239776769) result="176x144 - QSIF PAL"; ;;
            2332069889) result="352x288 - SIF_352 PAL"; ;;
            2399178753) result="480x288 - SIF_480 PAL"; ;;
            2399215617) result="480x576 - D1_480 PAL"; ;;
            2525044737) result="720x576 - D1_720 PAL"; ;;
            *)          result=$1; #just pass it back if we dont know what it is
            ;;
        esac
    fi
}

#Print help message about flag options
function helpmsg {
    /bin/echo -e "Usage:\n\t-l, --logs\n\t\tadditionally create a log file collection\n\t-h, --help\n\t\tshow this help message"
}

######Begin main logic
function main {
    #Checks and setup
    if [ -d /opt/haivision ]; then
        etcdir="/opt/haivision/etc"; 
        optdir="/opt/haivision";
        version="cent5"
        licensefile="license.dat"
        verfile="$etcdir/haivision-release"
    else
        if [ -d /opt/vf ]; then
            etcdir="/opt/vf/etc";
            optdir="/opt/vf";
            version="cent5"
            licensefile="license.dat"
            verfile="$etcdir/vfurnace-release"
        else
            etcdir="/etc/videofurnace"
            optdir="/opt/vf"; 
            version="cent3"
            licensefile="vfclamlicense.dat"
            verfile="$etcdir/vfurnace-release"
        fi
    fi
    
    #make sure user has the necessary privileges
    if [ ! "$(/usr/bin/whoami)" == "root" ]; then
        /bin/echo "You must either be root or run this as sudo."; exit;
    fi
    
    #create outfile
    if [ -d "$1" ]; then outfile="$1/$outfile"; fi
    > $outfile
    /bin/echo "Creating $outfile"
    /bin/echo "Please wait..."
    
    ##basic profile setup
    writeheader "Profile Info"
    /bin/grep -e PROFILENAME -e GROUPNAME -e HOSTNAME $etcdir/vfprofile >> $outfile
    
    if [ -e "$etcdir/$licensefile" ]; then
        writeheader "System License"
        /bin/cat "$etcdir/$licensefile" >> $outfile
    fi
    
    #time info & ntpq
    writeheader "Time Info"
    /bin/date >> $outfile
    searchinfile "/etc/sysconfig/clock" "\".*\"" "timezone:" "ZONE=";write "$result"
    searchinfile "/etc/cron.daily/ntpdate" "[0-9a-Z:_.-]*[[:blank:]]*$" "timeserver:" "ntpdate";write "$result"
    
    ##important info for pre-update checks
    writeheader "Machine Info" 
    write "---System MAC addresses---"
    write "$(/sbin/ifconfig | /bin/grep -i hwaddr)"
    write "\n--- $(/bin/cat $verfile) ---"
    
    ##network setup
    writeheader "Network Config"
    write "Current hostname: $(hostname)"
    write "\nResolv search:"
    
    searchinfile "/etc/resolv.conf" "[0-9a-Z:_.-]*[[:blank:]]*$" "" "search";write "$result" 
    write "\nnameservers:"
    searchinfile "/etc/resolv.conf" "[0-9a-Z:_.-]*[[:blank:]]*$" "" "nameserver";write "$result"
    write "\nProxy server from \$http_proxy: $(/bin/echo $http_proxy)"
   
    #squid 
    searchinfile "/etc/squid/squid.conf" "^[[:space:]]*cache_peer.*" "external proxy info from squid.conf:" "cache_peer";write "$result"
    
    #search for up to 4 NICs, bonds, or route files
    write "\nNetwork info dump:"
    /bin/cat /etc/sysconfig/network >> $outfile
    for y in $(/usr/bin/seq 0 3); do 
        for x in $(/bin/echo "ifcfg-eth ifcfg-bond route-eth route-bond"); do
            if [ -f /etc/sysconfig/network-scripts/$x$y ];then
                write "\n---$x$y---"
                /bin/cat /etc/sysconfig/network-scripts/$x$y >> $outfile
            fi
        done
    done
    
    write "\n---Routing table---"
    /sbin/route -n >> $outfile
    
    if [ -f /etc/snmp/snmpd.conf ];then
        write "\nSNMP configuration dump:"
        /bin/cat /etc/snmp/snmpd.conf >> $outfile
    fi
   
    searchinfile "/etc/mail/sendmail.cf" "^DS.*" "relay"; write "\nsendmail relay: ${result#relay DS}";
 
    ############# VF Software specific checks
    writeheader "VF misc conf file checks"
    
    ## customer dnsd address
    searchinfile "$etcdir/vfmdnsd.conf" "output.*$" "dnsd provisioning address: "
    write "$result"
    
    ## sessions enabled?
    searchinfile "$etcdir/vfstat2xml.conf" "^[[:blank:]]*sessions" "sessions"
    if [ "$result" ]; then
        searchinfile "$etcdir/vfstat2xml.conf" ".*secondsback.*" " -  "
        write "\nSessions enabled in vfstat2xml.conf $result"
    fi
    
    ##NVR checks
    searchinfile "$etcdir/vfnvrd.conf" "storage.*" "NVRD: ";write "\n$result"
    searchinfile "$etcdir/vfnvrd.conf" "transferrate.*" "NVRD: ";write "$result"
    searchinfile "$etcdir/vfnvrd.conf" "guidemode.*" "NVRD: ";write "$result"
    
    ##asset storage
    searchinfile "$etcdir/vfam.conf" "^volume.*" "Asset Volumes:\n ";write "\n$result"
    searchinfile "$etcdir/vfam.conf" "^storage.*" "Volume Assignments:\n ";write "$result"
    
    ##Archive
    searchinfile "$etcdir/vfarchived.conf" "^min-free-space.*" "Archive:";write "$result"
    
    #######Encoder configs
    /bin/rpm -qi vfencoder &>/dev/null
    if [ "$?" == "0" ]; then
        writeheader "Encoder Configuration"
        search="bitrate vcodec gop vinput vformat vchannel audiomode audiobr limitvbvunderflow limitvbvoverflow limitmbufoverflow limitvsyncerror"
        #some special mangling - check for the 'resolution' identifier that applies to the current card and version
        if [ "$version" == "cent3" ]; then search="$search resolution"; fi
        if [ "$version" == "cent5" ]; then search="$search outresolution_0"; fi
        for y in $(/usr/bin/seq 0 7);do
            if [ -f $etcdir/vfencoder$y.conf ];then
                write "\n---Encoder $y---"
                for x in $search;do
                    vfcodeconvert "$(/bin/grep -E "^$x " $etcdir/vfencoder$y.conf | /bin/cut -d " " -f 2)"
                    if [ "$result" ]; then write "$x $result"; fi
                done;
            fi;
        done
    fi
    
    ##source item info
    writeheader "Lineup Source Items"
    /usr/bin/psql -h localhost -U vf -d vf -c 'select cs_call_sign as callsign, cs_channel_number as Channel_Num,cs_num  as private, cs_output_url_pri as pri_output,cs_output_url_sec as sec_output, cs_encryption_type as Encryption from cfg_stations order by cs_channel_number;' >> $outfile
    
    #lineups
    writeheader "Lineup Information"
    
    nowtree=$(/usr/bin/psql -h localhost -U vf -d vf -c 'select cl_name, cl_tree_view_name as NowTreeName, cl_tree_view_description as NowTreeDescription, cl_nowtree_state as NowTreeState, cl_nowtree_category as ShowInGuide from cfg_lineups;')
    lineupnames=$(/bin/grep -E -o 'stationLineUpName="[a-Z0-9_-]*"' $etcdir/vfepg.conf.xml | /bin/cut -d '"' -f 2)
    
    for x in $(/bin/echo $lineupnames); do
        write "Name: $x"
        /bin/echo -n "EPG URL: " >> $outfile
        /bin/grep -A 1000 "stationLineUpName=\"$x" $etcdir/vfepg.conf.xml | /bin/grep outputURL -m1 | /bin/cut -d '>' -f2 | /bin/cut -d '<' -f1 >> $outfile
        write "\nVOD Tree Setup:"
        /bin/echo "$nowtree" | /usr/bin/head -2 >> $outfile
        /bin/echo "$nowtree" | /bin/grep -i -E "^ $x" >> $outfile
        write "\n--Lineup order--"
        /usr/bin/psql -h localhost -U vf -d vf -c 'select cfg_lineups.cl_name, cfg_lineupitems.cl_name, cl_isseparator from cfg_lineups inner join cfg_lineupitems on cfg_lineups.cl_guid = cfg_lineupitems.cl_guid order by cfg_lineups.cl_name, cfg_lineupitems.cl_displayid;' | /bin/grep -i -E "^ $x" | /bin/sed -e "s/t$/Separator/g" -e "s/f$//g" | /bin/cut -d '|' -f 2,3 >> $outfile
        write "\n-----------------------\n"
    done
    
    writeheader "vfclamdcmdline.xml dump"
    /bin/cat $etcdir/vfclamdcmdline.xml >> $outfile
    
    ## server assignments
    writeheader "Channel/Server Assignments"
    
    /usr/bin/psql -h localhost -U vf -d vf -c 'select cs_channel_number as Channel_Num, cs_num  as private,cs_call_sign as callsign, cs_server as server from cfg_stations order by cs_server;' >> $outfile
    
    ##boot script checks, primarily for network tweaks but other things too
    writeheader "rc.local dump"
    /bin/cat "/etc/rc.local" | /bin/grep -v "^#" >> $outfile #greping out commented lines
    
    writeheader "vf items in inittab"
    /bin/grep vf /etc/inittab >> $outfile
    
    #### Show vfconfigd-util and vfinit-util output
    writeheader "Show vfconfigd-util output"
    $optdir/usr/bin/vfconfigd-util | /bin/sed 's/[ \t]*[^ \t]*[ \t]*//' >> $outfile
    writeheader "vfconfigd summary - invited systems"
    $optdir/usr/bin/vfconfigd-util |  awk '$8 == "yes"' | awk '{print $2, $7, $4, $5, $1}' >> $outfile
    writeheader "Show vfinit-util output"
    $optdir/usr/bin/vfinit-util >> $outfile
   
    
 
    #### Show vfpasswd output
    writeheader "Show vfpasswd output"
    $optdir/usr/bin/vfpasswd config &>/dev/null
    if [ ! "$?" == "0" ]; then
        write "The command :vfpasswd config: does not exist in this version!\n"
    else
        $optdir/usr/bin/vfpasswd config | /bin/grep -v "ldap_query_password" | /bin/grep -v "account_manager_password" >> $outfile
    fi
    
    ##### /proc/ info
    # CPU info
    writeheader "CPU Info"
    /bin/cat /proc/cpuinfo >> $outfile
    
    # NVRAM info
    writeheader "NVRAM Info"
    /bin/cat /proc/driver/nvram >> $outfile
    
    # Memory info
    writeheader "Memory Info"
    /bin/cat /proc/meminfo >> $outfile
    
    # Kernel Version
    writeheader "Kernel Version"
    /bin/cat /proc/version >> $outfile
    
    ##### OMreport info
    if [ -e /opt/dell/srvadmin/bin/omreport ]; then
        # BIOS info
        writeheader "BIOS Info & Setup"
        /opt/dell/srvadmin/bin/omreport chassis bios >> $outfile
        write "\n"
        /opt/dell/srvadmin/bin/omreport chassis biossetup >> $outfile
        
        # memory banks
        writeheader "Memory Banks"
        /opt/dell/srvadmin/bin/omreport chassis memory >> $outfile
    
        # Disks and RAID
        writeheader "Disks and RAID"
        /opt/dell/srvadmin/bin/omreport storage controller controller=0 | /bin/grep -e '^Controllers' -e '^Status' -e '^Name' -e '^State' -e '^Firmware' | /usr/bin/head -5  >> $outfile
        write ' '
        /opt/dell/srvadmin/bin/omreport storage vdisk controller=0 | /bin/grep -e '^Controller' -e '^Name' -e '^State' >> $outfile
        write ' '
        /opt/dell/srvadmin/bin/omreport storage pdisk controller=0 | /bin/grep -e '^List' -e '^Name' -e '^State' >> $outfile
    else
        writeheader "Dell OpenManage utility is not installed! Cannot collect BIOS info, memory banks or disk/RAID status"
    fi
    
    ##### IPMItool info
    if [ -f /usr/bin/ipmitool ]; then
        if ( [ -e /dev/ipmi0 ] || [ -e /dev/ipmi/0 ] || [ -e /dev/ipmidev/0 ] ); then
            # firmware
            writeheader "IPMItool BMC Firmware"
            /usr/bin/ipmitool bmc info >> $outfile
            
            # power
            writeheader "IPMItool Chassis Status (Power)"
            /usr/bin/ipmitool chassis status >> $outfile
            
            # SEL list
            writeheader "IPMItool SEL Messages"
            /usr/bin/ipmitool sel list >> $outfile
        else
            writeheader "IPMI utility is not installed! BMC, chassis and hardware events cannot be determined."
        fi
    else
        writeheader "ipmitool is not installed! BMC, chassis and hardware events cannot be determined."
    fi
    
    ##### Disk utilization and inodes
    writeheader "Disk utilization and inodes"
    write "--1K-blocks--"
    /bin/df -lT >> $outfile
    write "\n--Inodes--"
    /bin/df -ilT >> $outfile
    
    ##### List of PCI devices
    writeheader "List of PCI devices"
    /sbin/lspci >> $outfile
    
    ##### Check of services
    writeheader "Check of services"
    /sbin/chkconfig --list >> $outfile
    
    ##### Show rpm versions of important packages
    writeheader "Show rpm versions of important packages"
    /bin/rpm -qa | /bin/grep -e 'vf' -e 'http' -e 'php' -e 'post' -e 'squid' -e 'open' -e 'tz' | /bin/sort -fu >> $outfile
    
    ##### SELinux Denials
    writeheader "SELinux Denials"
    /sbin/aureport -a -ts this-week >> $outfile
    
    #### Show output of top command
    writeheader "Show output of top command (3 dumps)"
    /usr/bin/top -b -d 3 -n 3 >> $outfile
    
    ##### Make output file readable by non-root user
    /bin/chown $realuser: $outfile
    /bin/chmod 0644 $outfile

    /bin/echo "Snapshot complete." 
}

#Create log files collection
function logfiles {
    main #run main logic first
    /bin/echo "Logfiles requested, please wait..."
    /bin/mkdir -p $logdir
    
    #copy vf files
    /bin/cp $optdir/var/log/videofurnace.log* $logdir
    /bin/cp $optdir/var/log/vfupdate.log $logdir
    /bin/cp $outfile $logdir
    /bin/cp /var/log/messages $logdir
    /bin/mkdir -p $logdir/audit/
    /bin/cp /var/log/audit/* $logdir/audit/
    /bin/cp /var/log/dmesg $logdir
    /bin/mkdir -p $logdir/httpd/
    /bin/cp /var/log/httpd/* $logdir/httpd/
    /bin/mkdir -p $logdir/etc/
    /bin/cp $optdir/etc/* $logdir/etc/
    /bin/cat /etc/fstab >> $logdir/etc/fstab

    #if there are squid logs, copy them as well
    if [ -d /var/log/squid ];then 
        /bin/mkdir -p $logdir/squid/
        /bin/cp /var/log/squid/* $logdir/squid/
    fi
    
    #copy two most recent DB backups
    backuppath="$optdir/var/tmp/pgsql-backups"
    oldestbackup=$(/bin/ls -tr1 $backuppath | /bin/grep ^f | /usr/bin/tail -1)
    oldbackup=$(/bin/ls -tr1 $backuppath | /bin/grep ^f | /usr/bin/tail -2 | /usr/bin/head -1)
    /bin/mkdir -p $logdir/db-backup/
    /bin/cp $backuppath/$oldestbackup $logdir/db-backup/
    /bin/cp $backuppath/$oldbackup $logdir/db-backup/
   
    #run script and send output to text file in the logsdir
    $optdir/usr/bin/vfconfigd-util > $logdir/vfconfigd-util-full-output.txt
    
    #change owner of the logs dir
    /bin/chown -R $realuser: $logdir
    
    #gzip logs folder
    /bin/echo "Compressing logs directory: $logdir.tar.gz"
    /bin/tar -czvf $logdir.tar.gz $logdir/* &>/dev/null
    
    #clean up old dirs
    if [ "$?" == "0" ]; then
        /bin/echo "Removing old logs directories"
        rm -r furnace-system-dump-$(hostname)-*/
    fi
    /bin/echo "Script complete, please submit either $outfile or $logdir.tar.gz"
}

##### Get Option Flags
# run main if no options
if [ $# -eq 0 ]; then
    main
fi

# translate long options to short
for arg ; do
    delim=""
    case "$arg" in
       --logs) args="${args}-l ";;
       --help) args="${args}-h ";;
       # pass through anything else
       *) [[ "${arg:0:1}" == "-" ]] || delim="\""; args="${args}${delim}${arg}${delim} ";;
    esac
done
# reset the translated args
eval set -- $args
# now we can process with getopt
while getopts ":lh" opt; do
    case $opt in
        l) logfiles ;;
        h) helpmsg ;;
        \?) /bin/echo "Invalid option: -$OPTARG" >&2 ;;
    esac
done
