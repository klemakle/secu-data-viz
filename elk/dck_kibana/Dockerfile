FROM ubuntu

RUN apt update
RUN apt-get -y install openssh-server iptables 
RUN apt install rsyslog -y
RUN apt install apt-transport-https gnupg2 uuid-runtime pwgen curl dirmngr -y
RUN apt install openjdk-11-jre-headless -y
RUN apt install sudo vim wget file  -y
RUN apt update
RUN curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch |sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/elastic.gpg

RUN echo "deb [signed-by=/etc/apt/trusted.gpg.d/elastic.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-7.x.list
RUN apt update -y
RUN apt list --upgradable
#RUN apt install elasticsearch -y
RUN apt install kibana logstash -y
#RUN apt install filebeat -y
RUN sed -i".bak" 's/^\#PermitRootLogin prohibit-password/PermitRootLogin Yes/' /etc/ssh/sshd_config
EXPOSE 22
EXPOSE 8888
EXPOSE 5601
COPY kibana.yml /etc/kibana/
COPY demo.sh /entrypoint.sh
RUN chown root.kibana /etc/kibana/kibana.yml
RUN chmod +x /entrypoint.sh
RUN echo "root:toto" | chpasswd
#CMD service kibana start
ENTRYPOINT ["/entrypoint.sh"]
#history > histo-ok.txt
