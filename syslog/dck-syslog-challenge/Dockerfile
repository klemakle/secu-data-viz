FROM ubuntu

RUN apt-get update &&  apt-get -y install nmap 
RUN apt-get -y install openssh-server &&  apt-get -y install iptables
RUN apt-get -y install net-tools &&  apt-get -y install tcpdump
RUN apt-get -y install vim 
RUN apt-get -y install syslog-ng 
RUN apt-get -y install mysql-client 
EXPOSE 22
EXPOSE 8888
EXPOSE 514
COPY sshd_config /etc/ssh/
COPY syslog-ng.conf /etc/syslog-ng/
COPY rsyslog.xml /etc/syslog-ng/patterndb.d/
COPY demo.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
RUN echo "root:toto" | chpasswd
RUN /etc/init.d/syslog-ng start
RUN echo "SYSLOGNG_OPTS=\"--no-caps\"" >> /etc/default/syslog-ng
ENTRYPOINT ["/entrypoint.sh"]
