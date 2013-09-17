#!/bin/bash

CSHOST="localhost"
CSPORT="988"
USR="user"
PWD="passwd"
NETCAT="nc"
DELAY=5

get_geo()
{
  eval "`echo "$2" | sed -e \"s/^.*${1} /${1}=/g\" -e 's/;.*$//g'`"
}

do_init()
{
  clear
  sline="`stty -a 2>/dev/null | grep rows 2>/dev/null`"
  get_geo rows "$sline"
  get_geo columns "$sline"
  [ "$rows" -eq 0 ] && rows=25
  [ "$columns" -eq 0 ] && columns=80
  rows=`expr $rows - 1`
  export rows columns

  tput init 2>/dev/null
  TI_ED="`tput ed 2>/dev/null`"
  TI_SC="`tput sc 2>/dev/null`"
  TI_RC="`tput rc 2>/dev/null`"
  TI_B0="`tput setb 0 2>/dev/null`"
  TI_B1="`tput setb 5 2>/dev/null`"
  TI_B2="`tput setb 1 2>/dev/null`"
  TI_IL="`tput il1 2>/dev/null`"
  TI_DL="`tput dl1 1 2>/dev/null`"
  TI_EL="`tput el 2>/dev/null`"
  export TI_ED TI_B0 TI_B1 TI_B2 TI_IL TI_DL TI_SC TI_RC TI_EL
}

monitor()
{
  $NETCAT -u $CSHOST $CSPORT | awk -W interactive -F"|" '
    BEGIN{
      line="---------------------------------------------------------------------";
      nuser=0;
      tabsize=(ENVIRON["columns"]-length(line))/2;
      tab=sprintf("%-*.*s", tabsize, tabsize, "");
      rows=ENVIRON["rows"];
      il=ENVIRON["TI_IL"];
      dl=ENVIRON["TI_DL"];
      sc=ENVIRON["TI_SC"];
      rc=ENVIRON["TI_RC"];
      b0=ENVIRON["TI_B0"];
      b1=ENVIRON["TI_B1"];
      b2=ENVIRON["TI_B2"];
      ed=ENVIRON["TI_ED"];
      el=ENVIRON["TI_EL"];
      csr(0, rows);
      printf("\n%s%s\n", b2, ed);
      print(tab "Nr User        A C Modus        Online  Sender");
      print(tab line);
      csr(5+nuser, rows);
      cup(5+nuser, 0);
      printf("%s%s", b0, ed);
      cup(rows, 0);
    }

    function csr(row1, row2)
    {
      system("tput csr "row1" "row2);
    }

    function cup(crow, ccol)
    {
      system("tput cup "crow" "ccol);
    }

    /^\[IB....\]/{
      nuser=0;
    }
    /^\[I.....\]/{
      if (($2!="c") && ($2!="m"))
        next;
      printf("%s", sc);
      cup(4+nuser, 0);
      ot=$12/60;
      otm=ot%60; ot/=60;
      oth=ot%24; ot/=24;
      if (ot<1)
        ots=sprintf("%d:%02dh", oth, otm);
      else
        ots=sprintf("%dt %dh", ot, oth);

      austate=0+$5;
      if (austate<0) austate=-austate;
      printf("%s%s%s%2d %-12.12s%d %d %-10.10s %8.8s  %s\n", b2, el,
             tab, $3, $4, austate, $6, $9, ots, $14);
      printf("%s", el);
      nuser++;
      csr(5+nuser, rows);
      printf("%s%s", rc, b0);
      next;
    }
    /^\[LOG...\]/{
      printf("%s%s\n", substr($0, 20, 8), substr($0, 35));
      next;
    }
    {
      next;
    }'
}

do_exit()
{
  trap - 1 2 15
  tput csr 0 $rows 2>/dev/null
  tput sgr0 2>/dev/null
  clear
  exit 0
}

do_init
trap do_exit 1 2 15

[ -n "$1" ] && CSHOST="$1"
[ -n "$2" ] && CSPORT="$2"

while true
do
  (
    while true
    do
      echo "login $USR $PWD"
      sleep 1
      echo "log on"
      sleep 1
      echo "status"
      sleep $DELAY
    done
  ) | monitor
done
